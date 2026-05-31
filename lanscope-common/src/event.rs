//! Discovery / sampled-packet events pushed kernel→userspace via a ring buffer.
//!
//! The eBPF side does *cheap* work: identify that a frame is interesting (ARP,
//! DHCP, mDNS, SSDP, a TLS ClientHello, …), copy the source MAC/IP plus a bounded
//! slice of bytes, and emit one [`Event`]. All *deep* protocol parsing happens in
//! userspace, where there is no verifier or stack-size constraint.

use crate::MacAddr;

/// Maximum bytes of packet payload carried in a single [`Event`].
///
/// Sized to comfortably hold a DHCP options block / mDNS answer / TLS
/// ClientHello prefix while keeping the ring-buffer record small.
pub const EVENT_PAYLOAD_LEN: usize = 512;

/// What kind of frame produced this event. Stored as a `u8` discriminant so the
/// record stays `#[repr(C)]`-stable across the boundary.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EventKind {
    /// First time this source MAC was seen on the segment.
    NewHost = 0,
    Arp = 1,
    Dhcp = 2,
    Mdns = 3,
    Ssdp = 4,
    /// A TLS ClientHello (for JA4-style fingerprinting in userspace).
    TlsHello = 5,
    Unknown = 255,
}

impl EventKind {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => EventKind::NewHost,
            1 => EventKind::Arp,
            2 => EventKind::Dhcp,
            3 => EventKind::Mdns,
            4 => EventKind::Ssdp,
            5 => EventKind::TlsHello,
            _ => EventKind::Unknown,
        }
    }
}

/// A fixed-size discovery event. `#[repr(C)]` so it round-trips the ring buffer
/// byte-for-byte.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Event {
    /// [`EventKind`] discriminant.
    pub kind: u8,
    pub _pad: [u8; 1],
    /// Number of valid bytes in `payload`.
    pub payload_len: u16,
    /// Source IPv4 (network order); 0 if not an IP frame (e.g. ARP-only).
    pub src_ip: u32,
    /// Source hardware address.
    pub src_mac: MacAddr,
    pub _pad2: [u8; 2],
    /// Bounded copy of the relevant packet bytes for userspace decode.
    pub payload: [u8; EVENT_PAYLOAD_LEN],
}

impl Event {
    pub fn kind(&self) -> EventKind {
        EventKind::from_u8(self.kind)
    }

    /// The valid prefix of `payload` as a slice.
    pub fn payload(&self) -> &[u8] {
        let n = (self.payload_len as usize).min(EVENT_PAYLOAD_LEN);
        &self.payload[..n]
    }
}

impl core::fmt::Debug for Event {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Event")
            .field("kind", &self.kind())
            .field("src_mac", &self.src_mac)
            .field("src_ip", &self.src_ip)
            .field("payload_len", &self.payload_len)
            .finish()
    }
}

impl Default for Event {
    fn default() -> Self {
        Self {
            kind: EventKind::Unknown as u8,
            _pad: [0; 1],
            payload_len: 0,
            src_ip: 0,
            src_mac: [0; 6],
            _pad2: [0; 2],
            payload: [0; EVENT_PAYLOAD_LEN],
        }
    }
}
