//! lanscope — passive eBPF IoT device fingerprinting & anomaly detection.
//!
//! The crate is organised as a pipeline of single-responsibility stages joined
//! by trait seams so each stage can be tested and replaced in isolation:
//!
//! ```text
//! CaptureBackend → decode → DeviceRegistry → Fingerprinter → AnomalyDetector
//!                                   │                              │
//!                                   └──────────► Store ◄───────────┘
//! ```

pub mod alert;
pub mod anomaly;
pub mod app;
pub mod capture;
pub mod cli;
pub mod config;
pub mod decode;
pub mod error;
pub mod exporter;
pub mod features;
pub mod fingerprint;
pub mod netfmt;
pub mod registry;
pub mod storage;
pub mod tui;

pub use error::{Error, Result};
