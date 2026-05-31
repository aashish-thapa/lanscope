//! Persistence.
//!
//! `Store` is the persistence seam: the pipeline depends on the trait, so the
//! SQLite implementation can be swapped for an in-memory fake in tests. The
//! concrete [`sqlite::SqliteStore`] is the production backing.

use crate::alert::Alert;
use crate::error::Result;
use crate::registry::Device;

pub mod sqlite;

/// Durable storage for devices and alerts.
pub trait Store: Send {
    /// Load all persisted device records (used to seed the registry at start).
    fn load_devices(&self) -> Result<Vec<Device>>;

    /// Insert or update a device by MAC.
    fn upsert_device(&self, device: &Device) -> Result<()>;

    /// Persist an anomaly alert.
    fn record_alert(&self, alert: &Alert) -> Result<()>;

    /// Most recent alerts, newest first, capped at `limit`.
    fn recent_alerts(&self, limit: usize) -> Result<Vec<Alert>>;
}
