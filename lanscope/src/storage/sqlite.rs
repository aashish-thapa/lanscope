//! SQLite-backed [`Store`].
//!
//! Uses the bundled SQLite (no system dependency) so `cargo install lanscope`
//! works out of the box. Variable-length fields (IPs, services) are stored as
//! JSON text columns — simple, queryable enough for this tool, and avoids a
//! join table for what is effectively a small per-device list.

use std::path::Path;

use rusqlite::{params, Connection};

use crate::alert::{Alert, Severity};
use crate::error::Result;
use crate::registry::Device;

use super::Store;

pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Open (creating if needed) the database at `path` and run migrations.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Open an in-memory database (for tests).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS devices (
                 mac               TEXT PRIMARY KEY,
                 vendor            TEXT,
                 hostname          TEXT,
                 ips               TEXT NOT NULL DEFAULT '[]',
                 services          TEXT NOT NULL DEFAULT '[]',
                 dhcp_fingerprint  TEXT,
                 dhcp_vendor_class TEXT,
                 device_type       TEXT,
                 first_seen        INTEGER NOT NULL,
                 last_seen         INTEGER NOT NULL,
                 packets           INTEGER NOT NULL DEFAULT 0,
                 bytes             INTEGER NOT NULL DEFAULT 0
             );
             CREATE TABLE IF NOT EXISTS alerts (
                 id        INTEGER PRIMARY KEY AUTOINCREMENT,
                 ts        INTEGER NOT NULL,
                 mac       TEXT,
                 severity  TEXT NOT NULL,
                 kind      TEXT NOT NULL,
                 message   TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts DESC);",
        )?;
        Ok(())
    }
}

impl Store for SqliteStore {
    fn load_devices(&self) -> Result<Vec<Device>> {
        let mut stmt = self.conn.prepare(
            "SELECT mac, vendor, hostname, ips, services, dhcp_fingerprint,
                    dhcp_vendor_class, device_type, first_seen, last_seen, packets, bytes
             FROM devices",
        )?;
        let rows = stmt.query_map([], |row| {
            let ips: String = row.get(3)?;
            let services: String = row.get(4)?;
            Ok(Device {
                mac: row.get(0)?,
                vendor: row.get(1)?,
                hostname: row.get(2)?,
                ips: serde_json::from_str(&ips).unwrap_or_default(),
                services: serde_json::from_str(&services).unwrap_or_default(),
                dhcp_fingerprint: row.get(5)?,
                dhcp_vendor_class: row.get(6)?,
                device_type: row.get(7)?,
                first_seen: row.get(8)?,
                last_seen: row.get(9)?,
                packets: row.get::<_, i64>(10)? as u64,
                bytes: row.get::<_, i64>(11)? as u64,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    fn upsert_device(&self, d: &Device) -> Result<()> {
        let ips = serde_json::to_string(&d.ips).unwrap_or_else(|_| "[]".into());
        let services = serde_json::to_string(&d.services).unwrap_or_else(|_| "[]".into());
        self.conn.execute(
            "INSERT INTO devices
                 (mac, vendor, hostname, ips, services, dhcp_fingerprint,
                  dhcp_vendor_class, device_type, first_seen, last_seen, packets, bytes)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
             ON CONFLICT(mac) DO UPDATE SET
                 vendor=excluded.vendor,
                 hostname=excluded.hostname,
                 ips=excluded.ips,
                 services=excluded.services,
                 dhcp_fingerprint=excluded.dhcp_fingerprint,
                 dhcp_vendor_class=excluded.dhcp_vendor_class,
                 device_type=excluded.device_type,
                 last_seen=excluded.last_seen,
                 packets=excluded.packets,
                 bytes=excluded.bytes",
            params![
                d.mac,
                d.vendor,
                d.hostname,
                ips,
                services,
                d.dhcp_fingerprint,
                d.dhcp_vendor_class,
                d.device_type,
                d.first_seen,
                d.last_seen,
                d.packets as i64,
                d.bytes as i64,
            ],
        )?;
        Ok(())
    }

    fn record_alert(&self, a: &Alert) -> Result<()> {
        self.conn.execute(
            "INSERT INTO alerts (ts, mac, severity, kind, message) VALUES (?1,?2,?3,?4,?5)",
            params![a.ts, a.mac, a.severity.as_str(), a.kind, a.message],
        )?;
        Ok(())
    }

    fn recent_alerts(&self, limit: usize) -> Result<Vec<Alert>> {
        let mut stmt = self.conn.prepare(
            "SELECT ts, mac, severity, kind, message FROM alerts ORDER BY ts DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit as i64], |row| {
            let sev: String = row.get(2)?;
            Ok(Alert {
                ts: row.get(0)?,
                mac: row.get(1)?,
                severity: sev.parse().unwrap_or(Severity::Info),
                kind: row.get(3)?,
                message: row.get(4)?,
            })
        })?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device() -> Device {
        Device {
            mac: "b8:27:eb:01:02:03".into(),
            vendor: Some("Raspberry Pi Foundation".into()),
            hostname: Some("pi".into()),
            ips: vec!["10.0.0.66".into()],
            services: vec!["_ssh._tcp.local".into()],
            dhcp_fingerprint: Some("1,3,6,15".into()),
            dhcp_vendor_class: None,
            device_type: None,
            first_seen: 100,
            last_seen: 200,
            packets: 10,
            bytes: 2048,
        }
    }

    #[test]
    fn device_roundtrip_and_upsert() {
        let store = SqliteStore::open_in_memory().unwrap();
        let mut d = sample_device();
        store.upsert_device(&d).unwrap();

        // Update path.
        d.last_seen = 300;
        d.bytes = 4096;
        store.upsert_device(&d).unwrap();

        let loaded = store.load_devices().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], d);
    }

    #[test]
    fn alerts_recent_order() {
        let store = SqliteStore::open_in_memory().unwrap();
        store
            .record_alert(&Alert::new(1, None, Severity::Info, "a", "first"))
            .unwrap();
        store
            .record_alert(&Alert::new(2, None, Severity::Critical, "b", "second"))
            .unwrap();
        let alerts = store.recent_alerts(10).unwrap();
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].message, "second");
    }
}
