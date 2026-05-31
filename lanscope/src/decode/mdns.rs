//! mDNS / Bonjour decoder.
//!
//! Pulls service types and `.local` hostnames out of an mDNS packet. A
//! `_service._tcp.local` name becomes a [`Signal::Service`]; a bare `host.local`
//! becomes a [`Signal::Hostname`].

use super::{dns, Signal};

pub fn decode(payload: &[u8]) -> Vec<Signal> {
    let mut signals = Vec::new();
    for name in dns::extract_names(payload) {
        if name.contains("._tcp") || name.contains("._udp") {
            signals.push(Signal::Service(name));
        } else if let Some(host) = name.strip_suffix(".local") {
            if !host.is_empty() && !host.starts_with('_') {
                signals.push(Signal::Hostname(host.to_string()));
            }
        }
    }
    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_bytes(labels: &[&str]) -> Vec<u8> {
        let mut v = Vec::new();
        for l in labels {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    #[test]
    fn detects_service_and_host() {
        let mut pkt = vec![0u8; 12];
        pkt.extend_from_slice(&name_bytes(&["_raspberrypi", "_tcp", "local"]));
        pkt.extend_from_slice(&name_bytes(&["livingroom-pi", "local"]));
        let sigs = decode(&pkt);
        assert!(sigs.contains(&Signal::Service("_raspberrypi._tcp.local".into())));
        assert!(sigs.contains(&Signal::Hostname("livingroom-pi".into())));
    }
}
