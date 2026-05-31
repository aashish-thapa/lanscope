//! Small formatting/parsing helpers for MACs and IPv4 addresses.

use lanscope_common::{Ipv4Be, MacAddr};

/// Render a MAC as lowercase colon-separated hex (`aa:bb:cc:dd:ee:ff`).
pub fn fmt_mac(mac: &MacAddr) -> String {
    let mut s = String::with_capacity(17);
    for (i, b) in mac.iter().enumerate() {
        if i > 0 {
            s.push(':');
        }
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Parse `aa:bb:cc:dd:ee:ff` (case-insensitive) into a [`MacAddr`].
pub fn parse_mac(s: &str) -> Option<MacAddr> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for slot in out.iter_mut() {
        *slot = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

/// Render an IPv4 address (network byte order) as dotted-quad.
pub fn fmt_ipv4(ip: Ipv4Be) -> String {
    let o = ip.to_be_bytes();
    format!("{}.{}.{}.{}", o[0], o[1], o[2], o[3])
}

/// Render a unix timestamp (seconds) as a compact UTC `YYYY-MM-DD HH:MM:SS`.
pub fn fmt_ts(unix_secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(unix_secs) {
        Ok(t) => format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            t.year(),
            u8::from(t.month()),
            t.day(),
            t.hour(),
            t.minute(),
            t.second(),
        ),
        Err(_) => unix_secs.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_roundtrip() {
        let mac = [0xb8, 0x27, 0xeb, 0x01, 0x02, 0x03];
        let s = fmt_mac(&mac);
        assert_eq!(s, "b8:27:eb:01:02:03");
        assert_eq!(parse_mac(&s), Some(mac));
    }

    #[test]
    fn mac_parse_rejects_garbage() {
        assert_eq!(parse_mac("not-a-mac"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee"), None);
        assert_eq!(parse_mac("aa:bb:cc:dd:ee:ff:00"), None);
    }

    #[test]
    fn ipv4_format() {
        assert_eq!(fmt_ipv4(0x0a00_0042), "10.0.0.66");
    }
}
