//! Portable capture backend.
//!
//! This backend works on any host with no eBPF toolchain. For M0/M1 it replays
//! a small set of synthetic-but-realistic discovery frames so the full pipeline
//! (decode → registry → fingerprint → store → UI) can be exercised and tested
//! end-to-end. A later milestone replaces the synthetic source with a real
//! `AF_PACKET` raw-socket reader (which needs CAP_NET_RAW) while keeping the
//! exact same [`CaptureBackend`] contract.

use lanscope_common::{Event, EventKind, FlowKey, FlowStats};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use super::{CaptureBackend, CaptureEvent};
use crate::config::Config;
use crate::error::Result;

pub struct PortableBackend {
    mode: crate::config::CaptureMode,
}

impl PortableBackend {
    pub fn new(config: &Config) -> Self {
        Self { mode: config.mode }
    }
}

impl CaptureBackend for PortableBackend {
    fn name(&self) -> &'static str {
        "portable"
    }

    fn spawn(
        self: Box<Self>,
        tx: mpsc::Sender<CaptureEvent>,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<Result<()>> {
        tokio::spawn(async move {
            tracing::info!(
                mode = self.mode.as_str(),
                "portable backend started (synthetic source)"
            );

            // Replay a few canned discovery frames so the pipeline has data.
            for ev in sample_events() {
                if tx
                    .send(CaptureEvent::Discovery(Box::new(ev)))
                    .await
                    .is_err()
                {
                    return Ok(());
                }
            }
            let _ = tx.send(CaptureEvent::Flows(sample_flows())).await;

            // Idle until asked to stop.
            loop {
                if *shutdown.borrow() {
                    break;
                }
                if shutdown.changed().await.is_err() {
                    break;
                }
            }
            tracing::debug!("portable backend stopped");
            Ok(())
        })
    }
}

/// Build a synthetic event with a MAC and raw payload.
fn event(kind: EventKind, mac: [u8; 6], src_ip: u32, payload: &[u8]) -> Event {
    let mut ev = Event {
        kind: kind as u8,
        src_mac: mac,
        src_ip,
        payload_len: payload.len() as u16,
        ..Event::default()
    };
    let n = payload.len().min(ev.payload.len());
    ev.payload[..n].copy_from_slice(&payload[..n]);
    ev
}

/// Encode dotted labels as a length-prefixed DNS name (wire format).
fn dns_name(labels: &[&str]) -> Vec<u8> {
    let mut v = Vec::new();
    for l in labels {
        v.push(l.len() as u8);
        v.extend_from_slice(l.as_bytes());
    }
    v.push(0);
    v
}

/// Build a minimal mDNS packet (12-byte header + two names).
fn mdns_packet() -> Vec<u8> {
    let mut p = vec![0u8; 12];
    p.extend_from_slice(&dns_name(&["_raspberrypi", "_tcp", "local"]));
    p.extend_from_slice(&dns_name(&["livingroom-pi", "local"]));
    p
}

/// Build a DHCP packet carrying hostname / param-request-list / vendor class.
fn dhcp_packet(hostname: &str, prl: &[u8], vendor: &str) -> Vec<u8> {
    let mut p = vec![0u8; 8];
    p.extend_from_slice(&[0x63, 0x82, 0x53, 0x63]); // magic cookie
    p.extend_from_slice(&[12, hostname.len() as u8]);
    p.extend_from_slice(hostname.as_bytes());
    p.extend_from_slice(&[55, prl.len() as u8]);
    p.extend_from_slice(prl);
    p.extend_from_slice(&[60, vendor.len() as u8]);
    p.extend_from_slice(vendor.as_bytes());
    p.push(255);
    p
}

/// A handful of representative discovery frames for demos/tests.
pub fn sample_events() -> Vec<Event> {
    let pi = [0xb8, 0x27, 0xeb, 0x01, 0x02, 0x03];
    let echo = [0x44, 0x65, 0x0d, 0xaa, 0xbb, 0xcc];
    vec![
        // A Raspberry Pi (OUI b8:27:eb) announcing itself over mDNS + DHCP.
        event(EventKind::NewHost, pi, 0x0a00_0042, &[]),
        event(EventKind::Mdns, pi, 0x0a00_0042, &mdns_packet()),
        event(EventKind::Dhcp, pi, 0x0a00_0042, &dhcp_packet("livingroom-pi", &[1, 3, 6, 15, 26, 28, 51, 58], "")),
        // An Amazon Echo (OUI 44:65:0d) advertising over SSDP.
        event(EventKind::NewHost, echo, 0x0a00_0050, &[]),
        event(EventKind::Ssdp, echo, 0x0a00_0050, b"NOTIFY * HTTP/1.1\r\nSERVER: Linux UPnP/1.0 AmazonEcho/1.0\r\nST: urn:schemas-upnp-org:device:basic:1\r\n\r\n"),
    ]
}

/// A synthetic flow snapshot.
pub fn sample_flows() -> Vec<(FlowKey, FlowStats)> {
    let key = FlowKey::new(0x0a00_0042, 0x0808_0808, 51514, 443, 6);
    let stats = FlowStats {
        packets: 42,
        bytes: 5_120,
        first_seen_ns: 1_000_000_000,
        last_seen_ns: 3_000_000_000,
        syn: 1,
        ack: 40,
        min_len: 60,
        max_len: 1500,
        ..FlowStats::default()
    };
    vec![(key, stats)]
}
