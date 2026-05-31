//! Userspace protocol decoders.
//!
//! Each decoder turns one raw [`Event`] payload into zero or more
//! [`Observation`]s — small, typed facts about a device. Decoders are pure
//! (`&[u8] -> Vec<...>`), so they are trivially unit-testable against captured
//! byte fixtures and carry no I/O or state.

use lanscope_common::{Event, EventKind, Ipv4Be, MacAddr};

pub mod dhcp;
pub mod dns;
pub mod mdns;
pub mod ssdp;

/// A typed fact extracted from a frame.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Signal {
    /// Device announced/observed a hostname.
    Hostname(String),
    /// An advertised service string (mDNS service type, SSDP server, …).
    Service(String),
    /// DHCP option-55 parameter-request-list fingerprint (comma-joined codes).
    DhcpFingerprint(String),
    /// DHCP option-60 vendor class identifier.
    DhcpVendorClass(String),
    /// Presence only (ARP / first sighting).
    Seen,
}

/// A [`Signal`] tagged with the device it pertains to.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Observation {
    pub mac: MacAddr,
    pub ip: Option<Ipv4Be>,
    pub signal: Signal,
}

/// Decode a single capture event into observations.
///
/// Dispatch is by [`EventKind`]; unknown kinds yield a bare `Seen` so presence
/// is still recorded.
pub fn decode_event(ev: &Event) -> Vec<Observation> {
    let ip = (ev.src_ip != 0).then_some(ev.src_ip);
    let mac = ev.src_mac;
    let payload = ev.payload();

    let signals: Vec<Signal> = match ev.kind() {
        EventKind::Dhcp => dhcp::decode(payload),
        EventKind::Mdns => mdns::decode(payload),
        EventKind::Ssdp => ssdp::decode(payload),
        EventKind::Arp | EventKind::NewHost => vec![Signal::Seen],
        EventKind::TlsHello => vec![Signal::Seen], // JA4 parsing lands in a later milestone
        EventKind::Unknown => vec![Signal::Seen],
    };

    signals
        .into_iter()
        .map(|signal| Observation { mac, ip, signal })
        .collect()
}
