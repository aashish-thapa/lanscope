//! Anomaly alert model, shared by the storage layer and the anomaly engine.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "info" => Ok(Severity::Info),
            "warning" => Ok(Severity::Warning),
            "critical" => Ok(Severity::Critical),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

/// A single anomaly finding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Alert {
    /// Unix seconds.
    pub ts: i64,
    /// Device this alert concerns (formatted MAC), if any.
    pub mac: Option<String>,
    pub severity: Severity,
    /// Machine-readable category, e.g. `new_device`, `port_scan`.
    pub kind: String,
    /// Human-readable description.
    pub message: String,
}

impl Alert {
    pub fn new(
        ts: i64,
        mac: Option<String>,
        severity: Severity,
        kind: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            ts,
            mac,
            severity,
            kind: kind.into(),
            message: message.into(),
        }
    }
}
