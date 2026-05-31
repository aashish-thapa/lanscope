//! Crate-wide error type. Library code returns [`Error`]; the binary layers
//! `anyhow` on top for context-rich reporting at the edges.

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("storage error: {0}")]
    Storage(#[from] rusqlite::Error),

    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("capture backend `{backend}` is unavailable: {reason}")]
    BackendUnavailable { backend: String, reason: String },

    #[error("the `{0}` capture backend requires building with `--features {0}`")]
    FeatureDisabled(&'static str),

    #[error("config error: {0}")]
    Config(String),

    #[error("model not found at {0}")]
    ModelNotFound(PathBuf),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
