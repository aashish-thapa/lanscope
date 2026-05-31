//! Flow identity and aggregate counters.
//!
//! A *flow* is a unidirectional 5-tuple. The eBPF data path keys a `HashMap`
//! by [`FlowKey`] and accumulates [`FlowStats`]; userspace drains the map
//! periodically and derives higher-level features (rates, inter-arrival
//! statistics, packet-size distribution) from the raw counters.

/// IANA L4 protocol numbers we care about. Stored as the raw `u8` on the wire.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Protocol {
    Icmp = 1,
    Tcp = 6,
    Udp = 17,
    Other = 255,
}

impl Protocol {
    /// Map a raw IP protocol byte to a known [`Protocol`].
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => Protocol::Other,
        }
    }
}

/// Unidirectional flow key (network byte order for addresses/ports).
///
/// `#[repr(C)]` with no padding holes so it is a valid eBPF map key.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub _pad: [u8; 3],
}

impl FlowKey {
    pub fn new(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16, protocol: u8) -> Self {
        Self {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
            _pad: [0; 3],
        }
    }
}

/// Aggregate counters for a flow, accumulated in-kernel.
///
/// All fields are monotonically increasing within a drain interval so the eBPF
/// side only ever does `+=` (no read-modify-write hazards beyond per-CPU
/// aggregation, which the map type handles).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct FlowStats {
    pub packets: u64,
    pub bytes: u64,
    /// Kernel monotonic nanoseconds of first/last packet in this flow.
    pub first_seen_ns: u64,
    pub last_seen_ns: u64,
    /// Counts of TCP control flags, for SYN-scan / RST-storm heuristics.
    pub syn: u32,
    pub fin: u32,
    pub rst: u32,
    pub ack: u32,
    /// Smallest / largest L3 packet length observed (payload fingerprinting).
    pub min_len: u16,
    pub max_len: u16,
}

impl FlowStats {
    /// Flow duration in seconds (0 if only one packet seen).
    pub fn duration_secs(&self) -> f64 {
        self.last_seen_ns.saturating_sub(self.first_seen_ns) as f64 / 1_000_000_000.0
    }

    /// Mean throughput in bytes/second over the flow's lifetime.
    pub fn bytes_per_sec(&self) -> f64 {
        let d = self.duration_secs();
        if d <= 0.0 {
            self.bytes as f64
        } else {
            self.bytes as f64 / d
        }
    }

    /// Mean packet size in bytes.
    pub fn mean_packet_len(&self) -> f64 {
        if self.packets == 0 {
            0.0
        } else {
            self.bytes as f64 / self.packets as f64
        }
    }
}
