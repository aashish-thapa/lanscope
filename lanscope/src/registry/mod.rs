//! In-memory device registry, keyed by MAC.
//!
//! The registry is the join point where per-frame [`Observation`]s and periodic
//! flow snapshots accumulate into a coherent [`Device`] record. It is pure
//! state + transitions (no I/O); persistence is the `storage` module's job and
//! the UI/exporter just read from it.

use std::collections::HashMap;

use lanscope_common::{FlowKey, FlowStats, Ipv4Be, MacAddr};
use serde::{Deserialize, Serialize};

use crate::decode::{Observation, Signal};
use crate::fingerprint::oui;
use crate::netfmt;

/// Cap on stored service strings per device, to bound memory on chatty hosts.
const MAX_SERVICES: usize = 32;

/// Everything we know about one device on the network.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Device {
    /// Stable identity (formatted MAC, e.g. `b8:27:eb:01:02:03`).
    pub mac: String,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    /// Observed IPv4 addresses (dotted-quad), most recent last.
    pub ips: Vec<String>,
    /// Advertised services (mDNS service types, SSDP banners).
    pub services: Vec<String>,
    pub dhcp_fingerprint: Option<String>,
    pub dhcp_vendor_class: Option<String>,
    /// Device-type guess (populated by the M3 fingerprint engine).
    pub device_type: Option<String>,
    /// Unix seconds.
    pub first_seen: i64,
    pub last_seen: i64,
    /// Cumulative traffic attributed to this device (from flow snapshots).
    pub packets: u64,
    pub bytes: u64,
}

impl Device {
    fn new(mac: MacAddr, now: i64) -> Self {
        Self {
            mac: netfmt::fmt_mac(&mac),
            vendor: oui::lookup(&mac).map(str::to_string),
            hostname: None,
            ips: Vec::new(),
            services: Vec::new(),
            dhcp_fingerprint: None,
            dhcp_vendor_class: None,
            device_type: None,
            first_seen: now,
            last_seen: now,
            packets: 0,
            bytes: 0,
        }
    }

    /// Best human label for the device: hostname → vendor → MAC.
    pub fn label(&self) -> &str {
        self.hostname
            .as_deref()
            .or(self.vendor.as_deref())
            .unwrap_or(&self.mac)
    }
}

/// Result of folding an observation in, so callers (e.g. the alert engine) can
/// react to first sightings.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Change {
    NewDevice,
    Updated,
}

#[derive(Default)]
pub struct DeviceRegistry {
    devices: HashMap<MacAddr, Device>,
}

impl DeviceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of known devices.
    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// Seed the registry from persisted records (parsed MACs).
    pub fn load(&mut self, mac: MacAddr, device: Device) {
        self.devices.insert(mac, device);
    }

    pub fn get(&self, mac: &MacAddr) -> Option<&Device> {
        self.devices.get(mac)
    }

    /// Record an inferred device type (set by the fingerprint engine, which
    /// lives outside the registry so the registry stays dependency-free).
    pub fn set_device_type(&mut self, mac: &MacAddr, device_type: Option<String>) {
        if let Some(d) = self.devices.get_mut(mac) {
            d.device_type = device_type;
        }
    }

    /// Iterate devices in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&MacAddr, &Device)> {
        self.devices.iter()
    }

    /// Fold one observation into the registry, returning the device's MAC and
    /// whether it was newly created.
    pub fn observe(&mut self, obs: &Observation, now: i64) -> (MacAddr, Change) {
        let mut change = Change::Updated;
        let dev = self.devices.entry(obs.mac).or_insert_with(|| {
            change = Change::NewDevice;
            Device::new(obs.mac, now)
        });
        dev.last_seen = now;

        if let Some(ip) = obs.ip {
            push_ip(dev, ip);
        }
        apply_signal(dev, &obs.signal);
        (obs.mac, change)
    }

    /// Attribute a flow snapshot's traffic to its source device (if known).
    ///
    /// Only meaningful when the backend sees other hosts' traffic (gateway/span);
    /// in host mode this mostly attributes the host's own flows.
    pub fn apply_flow(&mut self, key: &FlowKey, stats: &FlowStats, now: i64) {
        // Match by source IP against devices we've already discovered.
        let target = self
            .devices
            .values_mut()
            .find(|d| d.ips.iter().any(|ip| ip == &netfmt::fmt_ipv4(key.src_ip)));
        if let Some(dev) = target {
            dev.packets = dev.packets.saturating_add(stats.packets);
            dev.bytes = dev.bytes.saturating_add(stats.bytes);
            dev.last_seen = now;
        }
    }
}

fn push_ip(dev: &mut Device, ip: Ipv4Be) {
    let s = netfmt::fmt_ipv4(ip);
    if let Some(pos) = dev.ips.iter().position(|x| x == &s) {
        // Move to the end to mark as most-recent.
        let v = dev.ips.remove(pos);
        dev.ips.push(v);
    } else {
        dev.ips.push(s);
    }
}

fn apply_signal(dev: &mut Device, signal: &Signal) {
    match signal {
        Signal::Hostname(h) => {
            if dev.hostname.as_deref() != Some(h.as_str()) {
                dev.hostname = Some(h.clone());
            }
        }
        Signal::Service(s) => {
            if !dev.services.iter().any(|x| x == s) && dev.services.len() < MAX_SERVICES {
                dev.services.push(s.clone());
            }
        }
        Signal::DhcpFingerprint(f) => dev.dhcp_fingerprint = Some(f.clone()),
        Signal::DhcpVendorClass(v) => dev.dhcp_vendor_class = Some(v.clone()),
        Signal::Seen => {}
    }
}

/// Current wall-clock time in unix seconds.
pub fn now_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(mac: MacAddr, ip: Option<Ipv4Be>, signal: Signal) -> Observation {
        Observation { mac, ip, signal }
    }

    #[test]
    fn first_sighting_is_new_then_updates() {
        let mut reg = DeviceRegistry::new();
        let mac = [0xb8, 0x27, 0xeb, 1, 2, 3];
        let (_, c1) = reg.observe(&obs(mac, Some(0x0a00_0042), Signal::Seen), 100);
        assert_eq!(c1, Change::NewDevice);
        let (_, c2) = reg.observe(&obs(mac, None, Signal::Hostname("pi".into())), 200);
        assert_eq!(c2, Change::Updated);

        let d = reg.get(&mac).unwrap();
        assert_eq!(d.vendor.as_deref(), Some("Raspberry Pi Foundation"));
        assert_eq!(d.hostname.as_deref(), Some("pi"));
        assert_eq!(d.ips, vec!["10.0.0.66".to_string()]);
        assert_eq!(d.first_seen, 100);
        assert_eq!(d.last_seen, 200);
    }

    #[test]
    fn services_dedup() {
        let mut reg = DeviceRegistry::new();
        let mac = [0x44, 0x65, 0x0d, 1, 2, 3];
        reg.observe(&obs(mac, None, Signal::Service("a".into())), 1);
        reg.observe(&obs(mac, None, Signal::Service("a".into())), 2);
        reg.observe(&obs(mac, None, Signal::Service("b".into())), 3);
        assert_eq!(reg.get(&mac).unwrap().services, vec!["a", "b"]);
    }

    #[test]
    fn flow_attribution_by_ip() {
        let mut reg = DeviceRegistry::new();
        let mac = [0xb8, 0x27, 0xeb, 1, 2, 3];
        reg.observe(&obs(mac, Some(0x0a00_0042), Signal::Seen), 1);
        let key = FlowKey::new(0x0a00_0042, 0x0808_0808, 1234, 443, 6);
        let stats = FlowStats {
            packets: 10,
            bytes: 999,
            ..Default::default()
        };
        reg.apply_flow(&key, &stats, 5);
        let d = reg.get(&mac).unwrap();
        assert_eq!(d.packets, 10);
        assert_eq!(d.bytes, 999);
    }
}
