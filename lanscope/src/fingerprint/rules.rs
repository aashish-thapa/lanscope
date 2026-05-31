//! Rule-based fingerprinter.
//!
//! Each [`Rule`] is a case-insensitive substring matched against a "haystack"
//! built from all of a device's signals (services, vendor, DHCP vendor class,
//! hostname, DHCP fingerprint). The highest-confidence matching rule wins.
//!
//! Rules are ordered most-specific (a unique mDNS service or SSDP banner) to
//! least-specific (a bare OUI vendor), and confidences encode that: a service
//! match is strong evidence, an OUI match is weak (vendors make many products).
//! This is the pluggable, data-driven seam the plan's M3 calls for — extend by
//! adding rows, not code.

use crate::registry::Device;

use super::engine::{Category, Classification, Fingerprinter};

struct Rule {
    needle: &'static str,
    device_type: &'static str,
    category: Category,
    confidence: f32,
}

/// Ordered rule table. First the strong (protocol-advertised) signals, then
/// weak OUI-vendor fallbacks.
const RULES: &[Rule] = &[
    // --- strong: advertised services / SSDP banners ---
    Rule {
        needle: "amazonecho",
        device_type: "Amazon Echo",
        category: Category::SmartSpeaker,
        confidence: 0.95,
    },
    Rule {
        needle: "_googlecast",
        device_type: "Google Chromecast",
        category: Category::MediaStreamer,
        confidence: 0.92,
    },
    Rule {
        needle: "googlecast",
        device_type: "Google Chromecast",
        category: Category::MediaStreamer,
        confidence: 0.9,
    },
    Rule {
        needle: "sonos",
        device_type: "Sonos Speaker",
        category: Category::SmartSpeaker,
        confidence: 0.92,
    },
    Rule {
        needle: "roku",
        device_type: "Roku Streamer",
        category: Category::MediaStreamer,
        confidence: 0.9,
    },
    Rule {
        needle: "_raop",
        device_type: "AirPlay Device",
        category: Category::MediaStreamer,
        confidence: 0.85,
    },
    Rule {
        needle: "_airplay",
        device_type: "AirPlay Device",
        category: Category::MediaStreamer,
        confidence: 0.85,
    },
    Rule {
        needle: "spotify-connect",
        device_type: "Spotify Speaker",
        category: Category::SmartSpeaker,
        confidence: 0.8,
    },
    Rule {
        needle: "philips hue",
        device_type: "Philips Hue Bridge",
        category: Category::SmartLight,
        confidence: 0.92,
    },
    Rule {
        needle: "_hue",
        device_type: "Philips Hue Bridge",
        category: Category::SmartLight,
        confidence: 0.9,
    },
    Rule {
        needle: "lifx",
        device_type: "LIFX Bulb",
        category: Category::SmartLight,
        confidence: 0.9,
    },
    Rule {
        needle: "_ipp",
        device_type: "Network Printer",
        category: Category::Printer,
        confidence: 0.9,
    },
    Rule {
        needle: "_pdl-datastream",
        device_type: "Network Printer",
        category: Category::Printer,
        confidence: 0.9,
    },
    Rule {
        needle: "_printer",
        device_type: "Network Printer",
        category: Category::Printer,
        confidence: 0.9,
    },
    Rule {
        needle: "diskstation",
        device_type: "Synology NAS",
        category: Category::Nas,
        confidence: 0.9,
    },
    Rule {
        needle: "_smb",
        device_type: "File Server / NAS",
        category: Category::Nas,
        confidence: 0.6,
    },
    Rule {
        needle: "_raspberrypi",
        device_type: "Raspberry Pi",
        category: Category::SingleBoardComputer,
        confidence: 0.85,
    },
    Rule {
        needle: "_homekit",
        device_type: "HomeKit Accessory",
        category: Category::IoTSensor,
        confidence: 0.7,
    },
    Rule {
        needle: "_hap",
        device_type: "HomeKit Accessory",
        category: Category::IoTSensor,
        confidence: 0.7,
    },
    // --- medium: DHCP vendor class ---
    Rule {
        needle: "android-dhcp",
        device_type: "Android Phone/Tablet",
        category: Category::Phone,
        confidence: 0.85,
    },
    Rule {
        needle: "msft 5.0",
        device_type: "Windows PC",
        category: Category::Computer,
        confidence: 0.8,
    },
    // --- weak: OUI vendor fallback ---
    Rule {
        needle: "raspberry pi",
        device_type: "Raspberry Pi",
        category: Category::SingleBoardComputer,
        confidence: 0.7,
    },
    Rule {
        needle: "espressif",
        device_type: "ESP32/ESP8266 Module",
        category: Category::IoTSensor,
        confidence: 0.7,
    },
    Rule {
        needle: "nest labs",
        device_type: "Nest Device",
        category: Category::IoTSensor,
        confidence: 0.6,
    },
    Rule {
        needle: "lifx",
        device_type: "LIFX Bulb",
        category: Category::SmartLight,
        confidence: 0.65,
    },
    Rule {
        needle: "amazon",
        device_type: "Amazon Device",
        category: Category::SmartSpeaker,
        confidence: 0.55,
    },
    Rule {
        needle: "philips",
        device_type: "Philips Smart Device",
        category: Category::SmartLight,
        confidence: 0.55,
    },
    Rule {
        needle: "tp-link",
        device_type: "TP-Link Device",
        category: Category::Router,
        confidence: 0.5,
    },
    Rule {
        needle: "apple",
        device_type: "Apple Device",
        category: Category::Computer,
        confidence: 0.5,
    },
    Rule {
        needle: "google",
        device_type: "Google Device",
        category: Category::MediaStreamer,
        confidence: 0.5,
    },
];

/// The default fingerprinter used by the agent.
#[derive(Default)]
pub struct RuleFingerprinter;

impl RuleFingerprinter {
    pub fn new() -> Self {
        Self
    }
}

impl Fingerprinter for RuleFingerprinter {
    fn classify(&self, device: &Device) -> Option<Classification> {
        let haystack = build_haystack(device);
        RULES
            .iter()
            .filter(|r| haystack.contains(r.needle))
            .max_by(|a, b| a.confidence.total_cmp(&b.confidence))
            .map(|r| Classification {
                device_type: r.device_type.to_string(),
                category: r.category,
                confidence: r.confidence,
                rationale: format!("matched `{}`", r.needle),
            })
    }
}

/// Concatenate every textual signal into one lowercase string for matching.
fn build_haystack(d: &Device) -> String {
    let mut h = String::new();
    let mut push = |s: &str| {
        h.push_str(&s.to_ascii_lowercase());
        h.push('\n');
    };
    if let Some(v) = &d.vendor {
        push(v);
    }
    if let Some(v) = &d.dhcp_vendor_class {
        push(v);
    }
    if let Some(v) = &d.hostname {
        push(v);
    }
    for s in &d.services {
        push(s);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_with(vendor: Option<&str>, services: &[&str], vendor_class: Option<&str>) -> Device {
        Device {
            mac: "00:00:00:00:00:00".into(),
            vendor: vendor.map(str::to_string),
            hostname: None,
            ips: vec![],
            services: services.iter().map(|s| s.to_string()).collect(),
            dhcp_fingerprint: None,
            dhcp_vendor_class: vendor_class.map(str::to_string),
            device_type: None,
            first_seen: 0,
            last_seen: 0,
            packets: 0,
            bytes: 0,
        }
    }

    #[test]
    fn service_beats_vendor() {
        // Echo OUI (weak) + AmazonEcho SSDP banner (strong) → strong wins.
        let d = device_with(
            Some("Amazon Technologies"),
            &["server=Linux UPnP/1.0 AmazonEcho/1.0"],
            None,
        );
        let c = RuleFingerprinter::new().classify(&d).unwrap();
        assert_eq!(c.device_type, "Amazon Echo");
        assert_eq!(c.category, Category::SmartSpeaker);
        assert!(c.confidence > 0.9);
    }

    #[test]
    fn raspberry_pi_via_mdns() {
        let d = device_with(
            Some("Raspberry Pi Foundation"),
            &["_raspberrypi._tcp.local"],
            None,
        );
        let c = RuleFingerprinter::new().classify(&d).unwrap();
        assert_eq!(c.category, Category::SingleBoardComputer);
    }

    #[test]
    fn android_via_dhcp_vendor_class() {
        let d = device_with(None, &[], Some("android-dhcp-13"));
        let c = RuleFingerprinter::new().classify(&d).unwrap();
        assert_eq!(c.category, Category::Phone);
    }

    #[test]
    fn unknown_device_unclassified() {
        let d = device_with(None, &[], None);
        assert!(RuleFingerprinter::new().classify(&d).is_none());
    }
}
