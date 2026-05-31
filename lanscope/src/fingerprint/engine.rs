//! Fingerprinting abstraction.
//!
//! A [`Fingerprinter`] turns a device's accumulated signals into a best-guess
//! *type* with a confidence and a short rationale. It is a pure function of the
//! [`Device`] record, so it can run on every update and is trivially testable.

use crate::registry::Device;

/// Coarse device category, useful for UI grouping and anomaly baselining.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Category {
    SmartSpeaker,
    MediaStreamer,
    SmartLight,
    Camera,
    Thermostat,
    Printer,
    Phone,
    Computer,
    SingleBoardComputer,
    Router,
    Nas,
    IoTSensor,
    Unknown,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Category::SmartSpeaker => "smart-speaker",
            Category::MediaStreamer => "media-streamer",
            Category::SmartLight => "smart-light",
            Category::Camera => "camera",
            Category::Thermostat => "thermostat",
            Category::Printer => "printer",
            Category::Phone => "phone",
            Category::Computer => "computer",
            Category::SingleBoardComputer => "sbc",
            Category::Router => "router",
            Category::Nas => "nas",
            Category::IoTSensor => "iot-sensor",
            Category::Unknown => "unknown",
        }
    }
}

/// A classification result.
#[derive(Clone, Debug, PartialEq)]
pub struct Classification {
    pub device_type: String,
    pub category: Category,
    /// 0.0–1.0 confidence.
    pub confidence: f32,
    /// Which signal drove the match (for explainability).
    pub rationale: String,
}

/// Anything that can guess a device's type.
pub trait Fingerprinter: Send + Sync {
    fn classify(&self, device: &Device) -> Option<Classification>;
}
