//! Heuristic anomaly detectors.

use std::collections::{HashMap, HashSet};

use lanscope_common::{FlowKey, FlowStats};

use crate::alert::{Alert, Severity};
use crate::netfmt;
use crate::registry::{Change, Device};

use super::Detector;

/// Emits an alert the first time a device is seen.
pub struct NewDeviceDetector;

impl Detector for NewDeviceDetector {
    fn on_device(&mut self, device: &Device, change: Change, now: i64) -> Vec<Alert> {
        if change != Change::NewDevice {
            return Vec::new();
        }
        let vendor = device.vendor.as_deref().unwrap_or("unknown vendor");
        vec![Alert::new(
            now,
            Some(device.mac.clone()),
            Severity::Info,
            "new_device",
            format!("New device joined: {} ({vendor})", device.label()),
        )]
    }
}

/// Flags a source IP that contacts many distinct destination ports in a short
/// window — the classic horizontal/vertical port-scan signature.
pub struct PortScanDetector {
    /// Distinct destination ports seen per source IP in the current window.
    seen: HashMap<u32, ScanState>,
    window_secs: i64,
    threshold: usize,
}

struct ScanState {
    window_start: i64,
    ports: HashSet<u16>,
    alerted: bool,
}

impl Default for PortScanDetector {
    fn default() -> Self {
        Self {
            seen: HashMap::new(),
            window_secs: 10,
            threshold: 20,
        }
    }
}

impl Detector for PortScanDetector {
    fn on_flow(&mut self, key: &FlowKey, _stats: &FlowStats, now: i64) -> Vec<Alert> {
        let window = self.window_secs;
        let threshold = self.threshold;
        let state = self.seen.entry(key.src_ip).or_insert_with(|| ScanState {
            window_start: now,
            ports: HashSet::new(),
            alerted: false,
        });

        // Roll the window forward if it has elapsed.
        if now - state.window_start > window {
            state.window_start = now;
            state.ports.clear();
            state.alerted = false;
        }
        state.ports.insert(key.dst_port);

        if state.ports.len() >= threshold && !state.alerted {
            state.alerted = true;
            return vec![Alert::new(
                now,
                None,
                Severity::Warning,
                "port_scan",
                format!(
                    "Possible port scan from {}: {} distinct ports in {}s",
                    netfmt::fmt_ipv4(key.src_ip),
                    state.ports.len(),
                    window
                ),
            )];
        }
        Vec::new()
    }
}

/// Flags a source IP whose per-snapshot byte volume spikes well above its own
/// moving average — a coarse exfiltration / DDoS-participation signal.
pub struct VolumeSpikeDetector {
    ewma: HashMap<u32, f64>,
    /// Smoothing factor for the EWMA (0..1; higher = more reactive).
    alpha: f64,
    /// Multiple of the average that counts as a spike.
    spike_factor: f64,
    /// Ignore flows below this byte floor (avoids noise on tiny baselines).
    floor_bytes: f64,
}

impl Default for VolumeSpikeDetector {
    fn default() -> Self {
        Self {
            ewma: HashMap::new(),
            alpha: 0.3,
            spike_factor: 5.0,
            floor_bytes: 1_000_000.0, // 1 MB in a single snapshot
        }
    }
}

impl Detector for VolumeSpikeDetector {
    fn on_flow(&mut self, key: &FlowKey, stats: &FlowStats, now: i64) -> Vec<Alert> {
        let bytes = stats.bytes as f64;
        let avg = self.ewma.get(&key.src_ip).copied();
        // Update the EWMA before deciding, so the first observation just seeds it.
        let new_avg = match avg {
            Some(a) => self.alpha * bytes + (1.0 - self.alpha) * a,
            None => bytes,
        };
        self.ewma.insert(key.src_ip, new_avg);

        if let Some(a) = avg {
            if bytes > self.floor_bytes && a > 0.0 && bytes > self.spike_factor * a {
                return vec![Alert::new(
                    now,
                    None,
                    Severity::Warning,
                    "volume_spike",
                    format!(
                        "Traffic spike from {}: {:.0} bytes vs ~{:.0} avg",
                        netfmt::fmt_ipv4(key.src_ip),
                        bytes,
                        a
                    ),
                )];
            }
        }
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(mac: &str) -> Device {
        Device {
            mac: mac.into(),
            vendor: Some("Acme".into()),
            hostname: None,
            ips: vec![],
            services: vec![],
            dhcp_fingerprint: None,
            dhcp_vendor_class: None,
            device_type: None,
            first_seen: 0,
            last_seen: 0,
            packets: 0,
            bytes: 0,
        }
    }

    fn flow(src_ip: u32, dst_port: u16, bytes: u64) -> (FlowKey, FlowStats) {
        (
            FlowKey::new(src_ip, 0x01020304, 40000, dst_port, 6),
            FlowStats {
                bytes,
                packets: 1,
                ..Default::default()
            },
        )
    }

    #[test]
    fn new_device_alerts_once() {
        let mut d = NewDeviceDetector;
        assert_eq!(
            d.on_device(&dev("aa:bb:cc:00:11:22"), Change::NewDevice, 1)
                .len(),
            1
        );
        assert!(d
            .on_device(&dev("aa:bb:cc:00:11:22"), Change::Updated, 2)
            .is_empty());
    }

    #[test]
    fn port_scan_fires_past_threshold_then_silent() {
        let mut d = PortScanDetector::default();
        let mut alerts = 0;
        for port in 0..25u16 {
            let (k, s) = flow(0x0a000001, port, 100);
            alerts += d.on_flow(&k, &s, 0).len();
        }
        assert_eq!(alerts, 1, "should alert exactly once per window");
    }

    #[test]
    fn port_scan_resets_after_window() {
        let mut d = PortScanDetector::default();
        for port in 0..25u16 {
            let (k, s) = flow(0x0a000001, port, 100);
            d.on_flow(&k, &s, 0);
        }
        // New window, fresh scan → alerts again.
        let mut alerts = 0;
        for port in 100..125u16 {
            let (k, s) = flow(0x0a000001, port, 100);
            alerts += d.on_flow(&k, &s, 100).len();
        }
        assert_eq!(alerts, 1);
    }

    #[test]
    fn volume_spike_needs_baseline_then_fires() {
        let mut d = VolumeSpikeDetector::default();
        // Seed baseline with a modest flow → no alert.
        let (k, s) = flow(0x0a000002, 443, 10_000);
        assert!(d.on_flow(&k, &s, 0).is_empty());
        // Huge flow above floor and >5x average → alert.
        let (k2, s2) = flow(0x0a000002, 443, 50_000_000);
        assert_eq!(d.on_flow(&k2, &s2, 1).len(), 1);
    }
}
