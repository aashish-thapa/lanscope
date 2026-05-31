//! In-kernel capture backend (feature `ebpf`).
//!
//! Loads the compiled XDP program, attaches it to the configured interface, and
//! then bridges the two kernel maps into the [`CaptureEvent`] stream:
//!   * the `EVENTS` ring buffer → [`CaptureEvent::Discovery`] (polled via epoll),
//!   * the `FLOWS` hash map → [`CaptureEvent::Flows`] (drained on an interval,
//!     removing entries so each snapshot carries the delta since the last).
//!
//! Loading/attaching requires `CAP_BPF` + `CAP_NET_ADMIN`; on failure
//! [`super::select_backend`] falls back to the portable backend.

use std::mem;
use std::time::Duration;

use aya::maps::{HashMap as AyaHashMap, MapData, RingBuf};
use aya::programs::{Xdp, XdpFlags};
use aya::Ebpf;
use lanscope_common::{Event, FlowKey, FlowStats};
use tokio::io::unix::AsyncFd;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::{CaptureBackend, CaptureEvent};
use crate::config::Config;
use crate::error::{Error, Result};

/// XDP program function name, as exported by the eBPF crate.
const PROG_NAME: &str = "lanscope";

pub struct EbpfBackend {
    ebpf: Ebpf,
    drain_interval: Duration,
}

impl EbpfBackend {
    /// Load + attach the XDP program. Returns an error (→ fallback) if the
    /// object can't load or attach (e.g. insufficient privileges).
    pub fn new(config: &Config) -> Result<Self> {
        // The object is compiled and staged in OUT_DIR by build.rs.
        let bytes = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/lanscope"));
        let mut ebpf = Ebpf::load(bytes).map_err(|e| Error::BackendUnavailable {
            backend: "ebpf".into(),
            reason: format!("load: {e}"),
        })?;

        let program: &mut Xdp = ebpf
            .program_mut(PROG_NAME)
            .ok_or_else(|| Error::BackendUnavailable {
                backend: "ebpf".into(),
                reason: format!("program `{PROG_NAME}` not found in object"),
            })?
            .try_into()
            .map_err(|e| Error::BackendUnavailable {
                backend: "ebpf".into(),
                reason: format!("not an XDP program: {e}"),
            })?;

        program.load().map_err(|e| Error::BackendUnavailable {
            backend: "ebpf".into(),
            reason: format!("verifier/load: {e}"),
        })?;

        // Prefer driver/native mode; fall back to generic (skb) mode for NICs
        // or virtual interfaces without XDP offload.
        program
            .attach(&config.interface, XdpFlags::default())
            .or_else(|_| program.attach(&config.interface, XdpFlags::SKB_MODE))
            .map_err(|e| Error::BackendUnavailable {
                backend: "ebpf".into(),
                reason: format!("attach to {}: {e}", config.interface),
            })?;

        Ok(Self {
            ebpf,
            drain_interval: config.flow_drain_interval,
        })
    }
}

impl CaptureBackend for EbpfBackend {
    fn name(&self) -> &'static str {
        "ebpf-xdp"
    }

    fn spawn(
        self: Box<Self>,
        tx: mpsc::Sender<CaptureEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            let Self {
                mut ebpf,
                drain_interval,
            } = *self;

            let ring = RingBuf::try_from(
                ebpf.take_map("EVENTS")
                    .ok_or_else(|| internal("EVENTS map missing"))?,
            )
            .map_err(|e| internal(&format!("ring buffer: {e}")))?;
            let mut async_fd = AsyncFd::new(ring).map_err(Error::Io)?;

            let mut tick = tokio::time::interval(drain_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                tokio::select! {
                    readable = async_fd.readable_mut() => {
                        let mut guard = readable.map_err(Error::Io)?;
                        drain_events(guard.get_inner_mut(), &tx).await;
                        guard.clear_ready();
                    }
                    _ = tick.tick() => {
                        let flows = drain_flows(&mut ebpf);
                        if !flows.is_empty() && tx.send(CaptureEvent::Flows(flows)).await.is_err() {
                            break;
                        }
                    }
                    res = shutdown.changed() => {
                        if res.is_err() || *shutdown.borrow() { break; }
                    }
                }
            }
            tracing::debug!("ebpf backend stopped");
            Ok(())
        })
    }
}

/// Drain all currently-available ring-buffer records into the channel.
async fn drain_events(ring: &mut RingBuf<MapData>, tx: &mpsc::Sender<CaptureEvent>) {
    while let Some(item) = ring.next() {
        if item.len() >= mem::size_of::<Event>() {
            // SAFETY: the kernel wrote exactly one `Event` (repr(C)) here; read
            // unaligned since ring records carry no alignment guarantee.
            let ev = unsafe { std::ptr::read_unaligned(item.as_ptr() as *const Event) };
            if tx
                .send(CaptureEvent::Discovery(Box::new(ev)))
                .await
                .is_err()
            {
                return;
            }
        }
    }
}

/// Read every flow entry, then remove it, so each snapshot is the delta since
/// the previous drain.
fn drain_flows(ebpf: &mut Ebpf) -> Vec<(FlowKey, FlowStats)> {
    let mut out = Vec::new();
    {
        let Some(map) = ebpf.map("FLOWS") else {
            return out;
        };
        let Ok(flows) = AyaHashMap::<_, FlowKey, FlowStats>::try_from(map) else {
            return out;
        };
        for entry in flows.iter().flatten() {
            out.push(entry);
        }
    }
    if !out.is_empty() {
        if let Some(map) = ebpf.map_mut("FLOWS") {
            if let Ok(mut flows) = AyaHashMap::<_, FlowKey, FlowStats>::try_from(map) {
                for (key, _) in &out {
                    let _ = flows.remove(key);
                }
            }
        }
    }
    out
}

fn internal(msg: &str) -> Error {
    Error::BackendUnavailable {
        backend: "ebpf".into(),
        reason: msg.to_string(),
    }
}
