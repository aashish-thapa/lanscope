//! Capture abstraction — the seam that keeps the rest of the agent independent
//! of *how* packets are observed.
//!
//! The pipeline depends only on [`CaptureBackend`] and the [`CaptureEvent`]s it
//! emits, never on aya/eBPF directly (Dependency Inversion). That lets us:
//!   * build & test the whole agent on stable Rust with no eBPF toolchain, and
//!   * swap in the in-kernel backend (feature `ebpf`) with zero changes upstream.

use lanscope_common::{Event, FlowKey, FlowStats};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::error::Result;

#[cfg(feature = "ebpf")]
pub mod ebpf;
pub mod mock;

/// A unit of work produced by a backend and consumed by the pipeline.
#[derive(Clone, Debug)]
pub enum CaptureEvent {
    /// A decoded-in-userspace-later discovery frame (ARP/DHCP/mDNS/SSDP/TLS).
    Discovery(Box<Event>),
    /// A periodic snapshot of the kernel flow table (drained by the backend).
    Flows(Vec<(FlowKey, FlowStats)>),
}

/// A source of [`CaptureEvent`]s. Backends own their I/O thread/task and stop
/// when `shutdown` flips to `true`.
pub trait CaptureBackend: Send {
    /// Stable identifier for logs/metrics (e.g. `"ebpf-xdp"`, `"mock"`).
    fn name(&self) -> &'static str;

    /// Begin capturing. Events flow over `tx`; the backend returns once
    /// `shutdown` observes `true` (or on unrecoverable error).
    fn spawn(
        self: Box<Self>,
        tx: mpsc::Sender<CaptureEvent>,
        shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>>;
}

/// Pick the most capable backend available for `config`.
///
/// With `--features ebpf` this attempts the in-kernel backend and falls back to
/// the portable backend if attach fails; without it, the portable backend is
/// the only option.
pub fn select_backend(config: &crate::config::Config) -> Result<Box<dyn CaptureBackend>> {
    #[cfg(feature = "ebpf")]
    {
        match ebpf::EbpfBackend::new(config) {
            Ok(b) => {
                tracing::info!(backend = b.name(), iface = %config.interface, "using eBPF capture backend");
                return Ok(Box::new(b));
            }
            Err(e) => {
                tracing::warn!(error = %e, "eBPF backend unavailable, falling back to portable backend");
            }
        }
    }

    Ok(Box::new(mock::PortableBackend::new(config)))
}
