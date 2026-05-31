//! DHCP decoder.
//!
//! Extracts the three fields that matter for device fingerprinting:
//!   * option 12  — hostname,
//!   * option 55  — parameter request list (the classic DHCP fingerprint),
//!   * option 60  — vendor class identifier.
//!
//! We locate the BOOTP magic cookie (`0x63825363`) and walk the option TLVs
//! after it, which makes the decoder robust to exactly where the kernel side
//! started copying the packet.

use super::Signal;

const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
const OPT_PAD: u8 = 0;
const OPT_HOSTNAME: u8 = 12;
const OPT_PARAM_REQUEST_LIST: u8 = 55;
const OPT_VENDOR_CLASS: u8 = 60;
const OPT_END: u8 = 255;

pub fn decode(payload: &[u8]) -> Vec<Signal> {
    let Some(opts_start) = find_options(payload) else {
        return Vec::new();
    };
    let mut signals = Vec::new();
    let mut i = opts_start;

    while i < payload.len() {
        let code = payload[i];
        i += 1;
        match code {
            OPT_PAD => continue,
            OPT_END => break,
            _ => {}
        }
        let Some(&len) = payload.get(i) else { break };
        i += 1;
        let len = len as usize;
        let Some(data) = payload.get(i..i + len) else {
            break;
        };
        i += len;

        match code {
            OPT_HOSTNAME => {
                if let Ok(h) = std::str::from_utf8(data) {
                    let h = h.trim_matches(char::from(0)).trim();
                    if !h.is_empty() {
                        signals.push(Signal::Hostname(h.to_string()));
                    }
                }
            }
            OPT_PARAM_REQUEST_LIST => {
                let fp = data
                    .iter()
                    .map(|b| b.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                if !fp.is_empty() {
                    signals.push(Signal::DhcpFingerprint(fp));
                }
            }
            OPT_VENDOR_CLASS => {
                if let Ok(v) = std::str::from_utf8(data) {
                    let v = v.trim();
                    if !v.is_empty() {
                        signals.push(Signal::DhcpVendorClass(v.to_string()));
                    }
                }
            }
            _ => {}
        }
    }
    signals
}

/// Offset of the first option byte (just past the magic cookie), if present.
fn find_options(payload: &[u8]) -> Option<usize> {
    payload
        .windows(4)
        .position(|w| w == MAGIC_COOKIE)
        .map(|p| p + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_dhcp(hostname: &str, prl: &[u8], vendor: &str) -> Vec<u8> {
        let mut v = vec![0u8; 8]; // some BOOTP bytes before the cookie
        v.extend_from_slice(&MAGIC_COOKIE);
        v.push(OPT_HOSTNAME);
        v.push(hostname.len() as u8);
        v.extend_from_slice(hostname.as_bytes());
        v.push(OPT_PARAM_REQUEST_LIST);
        v.push(prl.len() as u8);
        v.extend_from_slice(prl);
        v.push(OPT_VENDOR_CLASS);
        v.push(vendor.len() as u8);
        v.extend_from_slice(vendor.as_bytes());
        v.push(OPT_END);
        v
    }

    #[test]
    fn extracts_all_three_fields() {
        let pkt = build_dhcp("nest-cam", &[1, 3, 6, 15, 119, 252], "android-dhcp-13");
        let sigs = decode(&pkt);
        assert!(sigs.contains(&Signal::Hostname("nest-cam".into())));
        assert!(sigs.contains(&Signal::DhcpFingerprint("1,3,6,15,119,252".into())));
        assert!(sigs.contains(&Signal::DhcpVendorClass("android-dhcp-13".into())));
    }

    #[test]
    fn no_cookie_yields_nothing() {
        assert!(decode(&[1, 2, 3, 4]).is_empty());
    }
}
