//! SSDP / UPnP decoder.
//!
//! SSDP rides on HTTP-over-UDP, so the payload is line-oriented text. We pull
//! the `SERVER` banner (great for OS/device identification) and the advertised
//! `NT`/`ST` device/service types.

use super::Signal;

pub fn decode(payload: &[u8]) -> Vec<Signal> {
    let text = String::from_utf8_lossy(payload);
    let mut signals = Vec::new();

    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim().to_ascii_uppercase().as_str() {
            "SERVER" => signals.push(Signal::Service(format!("server={value}"))),
            "NT" | "ST" => signals.push(Signal::Service(value.to_string())),
            _ => {}
        }
    }
    signals
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_server_and_st() {
        let payload = b"NOTIFY * HTTP/1.1\r\nSERVER: Linux/3.14 UPnP/1.0 AmazonEcho/1.0\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n";
        let sigs = decode(payload);
        assert!(sigs.contains(&Signal::Service(
            "server=Linux/3.14 UPnP/1.0 AmazonEcho/1.0".into()
        )));
        assert!(sigs.contains(&Signal::Service(
            "urn:schemas-upnp-org:device:MediaRenderer:1".into()
        )));
    }
}
