//! ONNX flow-classifier detector (feature `ml`).
//!
//! Wraps an ONNX model (trained offline from IoT-23 — see `ml/`) as just another
//! [`Detector`]. It scores each flow's [`crate::features`] vector and raises a
//! `Critical` alert when the malicious probability crosses a threshold. If no
//! model is supplied the detector simply isn't added, so the heuristic stack
//! keeps working — ML is purely additive.

use std::path::Path;

use lanscope_common::{FlowKey, FlowStats};
use ort::session::Session;
use ort::value::Value;

use crate::alert::{Alert, Severity};
use crate::error::{Error, Result};
use crate::features::{self, FEATURE_COUNT};
use crate::netfmt;

use super::Detector;

pub struct OnnxDetector {
    session: Session,
    threshold: f32,
}

impl OnnxDetector {
    /// Load a model from `path`. The model is expected to take a
    /// `[1, FEATURE_COUNT]` float input and emit a probability tensor whose last
    /// column is the malicious-class probability (train/export with `zipmap=False`).
    pub fn from_path(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Err(Error::ModelNotFound(path.to_path_buf()));
        }
        let session = Session::builder()
            .and_then(|mut b| b.commit_from_file(path))
            .map_err(|e| Error::Config(format!("failed to load ONNX model: {e}")))?;
        Ok(Self {
            session,
            threshold: 0.5,
        })
    }

    /// Run inference, returning the malicious-class probability if the model
    /// produced a usable output.
    fn score(&mut self, feats: &[f32; FEATURE_COUNT]) -> Option<f32> {
        let input = Value::from_array(([1usize, FEATURE_COUNT], feats.to_vec())).ok()?;
        let outputs = self.session.run(ort::inputs![input]).ok()?;
        // Find the first float tensor output and treat its last value as P(malicious).
        for (_name, value) in outputs.iter() {
            if let Ok((_shape, data)) = value.try_extract_tensor::<f32>() {
                if let Some(p) = data.last() {
                    return Some(*p);
                }
            }
        }
        None
    }
}

impl Detector for OnnxDetector {
    fn on_flow(&mut self, key: &FlowKey, stats: &FlowStats, now: i64) -> Vec<Alert> {
        let feats = features::extract(key, stats);
        match self.score(&feats) {
            Some(p) if p >= self.threshold => vec![Alert::new(
                now,
                None,
                Severity::Critical,
                "ml_malicious",
                format!(
                    "ML classifier flagged flow from {} → :{} (score {:.2})",
                    netfmt::fmt_ipv4(key.src_ip),
                    key.dst_port,
                    p
                ),
            )],
            _ => Vec::new(),
        }
    }
}
