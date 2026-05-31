//! Flow feature vector — the single source of truth shared by runtime inference
//! and the offline training pipeline.
//!
//! The Rust runtime extractor here and the Python training extractor in `ml/`
//! MUST agree on the exact set, order, and meaning of these features, or the
//! model will silently mispredict. [`FEATURE_NAMES`] is that contract: the
//! training pipeline references the same names in the same order.

use lanscope_common::{FlowKey, FlowStats};

/// Number of features per flow.
pub const FEATURE_COUNT: usize = 13;

/// Ordered feature names. Keep in lockstep with [`extract`] and `ml/features.py`.
pub const FEATURE_NAMES: [&str; FEATURE_COUNT] = [
    "duration_secs",
    "packets",
    "bytes",
    "bytes_per_sec",
    "mean_packet_len",
    "min_len",
    "max_len",
    "syn",
    "fin",
    "rst",
    "ack",
    "protocol",
    "dst_port",
];

/// Extract the feature vector for one flow.
pub fn extract(key: &FlowKey, stats: &FlowStats) -> [f32; FEATURE_COUNT] {
    [
        stats.duration_secs() as f32,
        stats.packets as f32,
        stats.bytes as f32,
        stats.bytes_per_sec() as f32,
        stats.mean_packet_len() as f32,
        stats.min_len as f32,
        stats.max_len as f32,
        stats.syn as f32,
        stats.fin as f32,
        stats.rst as f32,
        stats.ack as f32,
        key.protocol as f32,
        key.dst_port as f32,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_match_count() {
        assert_eq!(FEATURE_NAMES.len(), FEATURE_COUNT);
    }

    #[test]
    fn golden_vector() {
        // A 2-second, 42-packet/5120-byte TCP flow to port 443.
        let key = FlowKey::new(0x0a00_0001, 0x0808_0808, 5000, 443, 6);
        let stats = FlowStats {
            packets: 42,
            bytes: 5120,
            first_seen_ns: 1_000_000_000,
            last_seen_ns: 3_000_000_000,
            syn: 1,
            fin: 0,
            rst: 0,
            ack: 40,
            min_len: 60,
            max_len: 1500,
        };
        let f = extract(&key, &stats);
        assert_eq!(f[0], 2.0); // duration_secs
        assert_eq!(f[1], 42.0); // packets
        assert_eq!(f[2], 5120.0); // bytes
        assert_eq!(f[3], 2560.0); // bytes_per_sec = 5120/2
        assert!((f[4] - (5120.0 / 42.0)).abs() < 1e-3); // mean_packet_len
        assert_eq!(f[7], 1.0); // syn
        assert_eq!(f[10], 40.0); // ack
        assert_eq!(f[11], 6.0); // protocol = TCP
        assert_eq!(f[12], 443.0); // dst_port
    }
}
