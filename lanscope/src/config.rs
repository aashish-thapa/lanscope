//! Runtime configuration: capture mode, interface, paths, intervals.

use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

/// Where the tool sits on the network — this determines what traffic eBPF can
/// actually see and therefore how much of the feature set is usable.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CaptureMode {
    /// Host is the router/gateway: XDP on the LAN-facing interface sees *all*
    /// device traffic. Full per-device flow features + ML are available.
    Gateway,
    /// Host receives a switch SPAN/mirror feed: same visibility as gateway,
    /// without being inline (no forwarding risk).
    Span,
    /// Ordinary host: sees its own traffic plus broadcast/multicast. Discovery
    /// (ARP/DHCP/mDNS/SSDP) works; whole-LAN flow ML does not.
    #[default]
    Host,
}

impl CaptureMode {
    /// Whether this mode can observe traffic between *other* hosts.
    pub fn sees_whole_lan(self) -> bool {
        matches!(self, CaptureMode::Gateway | CaptureMode::Span)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            CaptureMode::Gateway => "gateway",
            CaptureMode::Span => "span",
            CaptureMode::Host => "host",
        }
    }
}

impl FromStr for CaptureMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "gateway" | "gw" => Ok(CaptureMode::Gateway),
            "span" | "mirror" => Ok(CaptureMode::Span),
            "host" | "local" => Ok(CaptureMode::Host),
            other => Err(format!(
                "unknown capture mode `{other}` (expected gateway|span|host)"
            )),
        }
    }
}

/// Fully resolved configuration for a capture session.
#[derive(Clone, Debug)]
pub struct Config {
    pub mode: CaptureMode,
    pub interface: String,
    /// SQLite database path.
    pub db_path: PathBuf,
    /// How often userspace drains the eBPF flow map.
    pub flow_drain_interval: Duration,
    /// Optional ONNX model path (used only with `--features ml`).
    pub model_path: Option<PathBuf>,
}

impl Config {
    pub fn new(mode: CaptureMode, interface: impl Into<String>) -> Self {
        Self {
            mode,
            interface: interface.into(),
            db_path: default_db_path(),
            flow_drain_interval: Duration::from_secs(2),
            model_path: None,
        }
    }
}

/// Default on-disk location for the device/flow database.
pub fn default_db_path() -> PathBuf {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("lanscope").join("lanscope.db")
}
