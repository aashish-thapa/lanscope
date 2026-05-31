//! Prometheus metrics exporter.
//!
//! Optional (`run --metrics <ADDR>`): installs a global recorder and serves
//! `/metrics` over HTTP so the agent can be scraped on a server/Pi deployment.
//! The rest of the code just calls the lightweight `metrics` macros; if no
//! exporter is installed those are cheap no-ops, so instrumentation is
//! unconditional and decoupled from whether scraping is enabled.

use std::net::SocketAddr;

use metrics::{counter, gauge};
use metrics_exporter_prometheus::PrometheusBuilder;

use crate::alert::Severity;
use crate::error::{Error, Result};

/// Install the Prometheus recorder and start the HTTP listener on `addr`.
pub fn install(addr: SocketAddr) -> Result<()> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()
        .map_err(|e| Error::Config(format!("failed to start metrics exporter on {addr}: {e}")))?;
    tracing::info!(%addr, "prometheus exporter listening at /metrics");
    Ok(())
}

/// Current number of known devices.
pub fn set_device_count(n: usize) {
    gauge!("lanscope_devices_total").set(n as f64);
}

/// Count a processed flow's traffic.
pub fn record_flow(packets: u64, bytes: u64) {
    counter!("lanscope_flow_packets_total").increment(packets);
    counter!("lanscope_flow_bytes_total").increment(bytes);
}

/// Count an emitted alert, labelled by severity.
pub fn record_alert(severity: Severity) {
    counter!("lanscope_alerts_total", "severity" => severity.as_str()).increment(1);
}
