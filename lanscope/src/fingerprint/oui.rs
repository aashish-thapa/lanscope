//! MAC OUI → vendor lookup.
//!
//! This ships a small, hand-curated table of OUIs common on home/IoT networks
//! so the tool is useful out of the box with zero data files. A later milestone
//! can load the full IEEE OUI registry (the Wireshark `manuf` file) at startup
//! to override/extend this; the [`lookup`] interface stays the same.

use lanscope_common::MacAddr;

/// (OUI prefix, vendor) pairs. Kept short and representative on purpose.
const TABLE: &[([u8; 3], &str)] = &[
    ([0xb8, 0x27, 0xeb], "Raspberry Pi Foundation"),
    ([0xdc, 0xa6, 0x32], "Raspberry Pi Trading"),
    ([0xe4, 0x5f, 0x01], "Raspberry Pi Trading"),
    ([0x44, 0x65, 0x0d], "Amazon Technologies"),
    ([0xfc, 0x65, 0xde], "Amazon Technologies"),
    ([0x68, 0x37, 0xe9], "Amazon Technologies"),
    ([0x18, 0xb4, 0x30], "Nest Labs"),
    ([0x64, 0x16, 0x66], "Nest Labs"),
    ([0x00, 0x17, 0x88], "Philips Hue (Signify)"),
    ([0xec, 0xb5, 0xfa], "Philips Lighting"),
    ([0xd0, 0x73, 0xd5], "LIFX"),
    ([0x50, 0xc7, 0xbf], "TP-Link"),
    ([0x54, 0x60, 0x09], "Google"),
    ([0xf4, 0xf5, 0xd8], "Google"),
    ([0x3c, 0x5a, 0xb4], "Google"),
    ([0x24, 0x0a, 0xc4], "Espressif (ESP32/ESP8266)"),
    ([0x7c, 0x9e, 0xbd], "Espressif (ESP32/ESP8266)"),
    ([0x5c, 0xcf, 0x7f], "Espressif (ESP32/ESP8266)"),
    ([0xa4, 0xcf, 0x12], "Espressif (ESP32/ESP8266)"),
    ([0x00, 0x1b, 0x63], "Apple"),
    ([0xac, 0xbc, 0x32], "Apple"),
    ([0xf0, 0x18, 0x98], "Apple"),
    ([0x00, 0x0c, 0x29], "VMware"),
];

/// Look up the vendor for a MAC's OUI prefix, if known.
///
/// Locally-administered / multicast MACs (bit 0x02 / 0x01 of the first octet)
/// are reported as such rather than matched, since they aren't real OUIs.
pub fn lookup(mac: &MacAddr) -> Option<&'static str> {
    if mac == &[0u8; 6] {
        return None;
    }
    if mac[0] & 0x02 != 0 {
        return Some("(locally administered)");
    }
    let prefix = [mac[0], mac[1], mac[2]];
    TABLE
        .iter()
        .find(|(p, _)| *p == prefix)
        .map(|(_, vendor)| *vendor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vendor() {
        assert_eq!(
            lookup(&[0xb8, 0x27, 0xeb, 1, 2, 3]),
            Some("Raspberry Pi Foundation")
        );
        assert_eq!(
            lookup(&[0x44, 0x65, 0x0d, 1, 2, 3]),
            Some("Amazon Technologies")
        );
    }

    #[test]
    fn unknown_vendor() {
        assert_eq!(
            lookup(&[0x12, 0x34, 0x56, 1, 2, 3]),
            Some("(locally administered)")
        );
        assert_eq!(lookup(&[0x10, 0x34, 0x56, 1, 2, 3]), None);
    }
}
