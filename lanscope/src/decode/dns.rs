//! Minimal DNS name extraction, sufficient for mDNS service/host discovery.
//!
//! We deliberately do *not* implement a full DNS parser: for fingerprinting we
//! only need the human-readable names (`_service._tcp.local`, `host.local`),
//! which live uncompressed in the mDNS question section. We scan for valid
//! length-prefixed label runs and keep the ones that look like service/host
//! names.

/// Read one length-prefixed DNS name starting at `start`.
///
/// Returns the dotted name and the offset just past the terminating zero byte.
/// Compression pointers (`0xC0`) terminate the read (we don't follow them).
pub fn read_name(buf: &[u8], start: usize) -> Option<(String, usize)> {
    let mut pos = start;
    let mut labels: Vec<String> = Vec::new();

    loop {
        let len = *buf.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), pos + 1));
        }
        // Compression pointer or reserved bits: stop here.
        if len & 0xC0 != 0 {
            if labels.is_empty() {
                return None;
            }
            return Some((labels.join("."), pos + 2));
        }
        pos += 1;
        let end = pos + len;
        let label = buf.get(pos..end)?;
        // Labels are ASCII; reject anything non-printable so we don't latch
        // onto binary RDATA that happens to start with a small length byte.
        if !label.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos = end;
    }
}

/// Extract plausible mDNS service/host names from a packet.
pub fn extract_names(buf: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut pos = 0;
    while pos < buf.len() {
        if let Some((name, _)) = read_name(buf, pos) {
            if is_interesting(&name) && !out.contains(&name) {
                out.push(name);
            }
        }
        pos += 1;
    }
    out
}

/// Keep names that look like mDNS service types or `.local` hosts.
fn is_interesting(name: &str) -> bool {
    let n = name.len();
    (3..=255).contains(&n)
        && (name.ends_with(".local") || name.contains("._tcp") || name.contains("._udp"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `_http._tcp.local` encoded as length-prefixed labels.
    fn http_service() -> Vec<u8> {
        let mut v = Vec::new();
        for label in ["_http", "_tcp", "local"] {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v
    }

    #[test]
    fn reads_service_name() {
        let buf = http_service();
        let (name, next) = read_name(&buf, 0).unwrap();
        assert_eq!(name, "_http._tcp.local");
        assert_eq!(next, buf.len());
    }

    #[test]
    fn extracts_from_mdns_with_header() {
        // 12-byte DNS header, then the question name.
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&http_service());
        let names = extract_names(&pkt);
        assert!(
            names.contains(&"_http._tcp.local".to_string()),
            "got {names:?}"
        );
    }

    #[test]
    fn rejects_binary_noise() {
        let noise = [5u8, 0xff, 0x00, 0xfe, 0x01, 0x02];
        assert!(extract_names(&noise).is_empty());
    }
}
