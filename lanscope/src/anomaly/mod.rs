//! Anomaly detection.
//!
//! Detection is split into small, single-purpose [`Detector`]s composed by an
//! [`Engine`]. Each detector reacts to the two event streams (device updates and
//! flow snapshots) and emits [`Alert`]s. Detectors are stateful but pure of I/O,
//! and take an explicit `now`, so they're deterministic and unit-testable.
//!
//! M4 ships heuristic detectors. The same `Detector` trait is the seam an ONNX
//! flow scorer (M6) plugs into — it's just another detector.

use lanscope_common::{FlowKey, FlowStats};

use crate::alert::Alert;
use crate::registry::{Change, Device};

pub mod heuristics;
#[cfg(feature = "ml")]
pub mod onnx;

/// A single anomaly heuristic. Implement only the hooks you need.
pub trait Detector: Send {
    /// React to a device being created or updated.
    fn on_device(&mut self, _device: &Device, _change: Change, _now: i64) -> Vec<Alert> {
        Vec::new()
    }

    /// React to a flow seen in a snapshot.
    fn on_flow(&mut self, _key: &FlowKey, _stats: &FlowStats, _now: i64) -> Vec<Alert> {
        Vec::new()
    }
}

/// Fans events out to a set of detectors and concatenates their alerts.
#[derive(Default)]
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
}

impl Engine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style registration.
    pub fn with(mut self, detector: Box<dyn Detector>) -> Self {
        self.detectors.push(detector);
        self
    }

    /// The default heuristic stack.
    pub fn default_stack() -> Self {
        use heuristics::{NewDeviceDetector, PortScanDetector, VolumeSpikeDetector};
        Self::new()
            .with(Box::new(NewDeviceDetector))
            .with(Box::new(PortScanDetector::default()))
            .with(Box::new(VolumeSpikeDetector::default()))
    }

    pub fn on_device(&mut self, device: &Device, change: Change, now: i64) -> Vec<Alert> {
        self.detectors
            .iter_mut()
            .flat_map(|d| d.on_device(device, change, now))
            .collect()
    }

    pub fn on_flow(&mut self, key: &FlowKey, stats: &FlowStats, now: i64) -> Vec<Alert> {
        self.detectors
            .iter_mut()
            .flat_map(|d| d.on_flow(key, stats, now))
            .collect()
    }
}
