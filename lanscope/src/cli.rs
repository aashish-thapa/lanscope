//! Command-line surface (clap derive). The CLI is a thin parsing layer; all
//! behaviour lives in [`crate::app`].

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use crate::config::CaptureMode;

#[derive(Parser, Debug)]
#[command(
    name = "lanscope",
    version,
    about = "Passive eBPF IoT device fingerprinting & anomaly detection",
    long_about = "lanscope passively fingerprints every device on your LAN and flags \
                  anomalous behaviour. Visibility depends on placement: gateway/span modes \
                  see all device traffic; host mode sees discovery + the host's own flows."
)]
pub struct Cli {
    /// Override the SQLite database path.
    #[arg(long, global = true, value_name = "PATH")]
    pub db: Option<PathBuf>,

    /// Increase log verbosity (-v, -vv). Overridden by RUST_LOG if set.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Start the capture daemon (TUI by default; --headless for servers).
    Run(RunArgs),
    /// One-shot: print the device table and exit (no TUI).
    List {
        /// Emit JSON instead of a table.
        #[arg(long)]
        json: bool,
    },
    /// Show detail for one device by MAC address.
    Device {
        /// MAC address, e.g. `aa:bb:cc:dd:ee:ff`.
        mac: String,
    },
    /// Show recent anomaly alerts.
    Alerts {
        /// Max number of alerts to show.
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Export the device/flow database.
    Export {
        #[arg(long, value_enum, default_value_t = ExportFormat::Json)]
        format: ExportFormat,
    },
}

#[derive(clap::Args, Debug)]
pub struct RunArgs {
    /// Network interface to attach to (e.g. eth0). Defaults to host mode auto-pick.
    #[arg(short, long)]
    pub interface: Option<String>,

    /// Capture mode: gateway | span | host.
    #[arg(short, long, default_value_t = CaptureMode::Host)]
    pub mode: CaptureMode,

    /// Run without the TUI: structured logs + Prometheus exporter only.
    #[arg(long)]
    pub headless: bool,

    /// Serve Prometheus metrics at this address (e.g. 0.0.0.0:9184).
    #[arg(long, value_name = "ADDR")]
    pub metrics: Option<std::net::SocketAddr>,

    /// Path to an ONNX anomaly model (requires building with --features ml).
    #[arg(long, value_name = "PATH")]
    pub model: Option<PathBuf>,
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum ExportFormat {
    Json,
    Csv,
}

// Let clap parse CaptureMode directly from its FromStr impl.
impl std::fmt::Display for CaptureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
