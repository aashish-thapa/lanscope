//! Application orchestration — the composition root.
//!
//! `app` is the only module that knows how all the pieces fit together: it
//! parses nothing (that's `cli`) and observes nothing (that's `capture`); it
//! wires concrete implementations into the pipeline and runs them.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{mpsc, watch};

use crate::alert::{Alert, Severity};
use crate::anomaly::Engine as AnomalyEngine;
use crate::capture::{self, CaptureEvent};
use crate::cli::{Cli, Command, ExportFormat, RunArgs};
use crate::config::{CaptureMode, Config};
use crate::decode::decode_event;
use crate::error::{Error, Result};
use crate::fingerprint::{Fingerprinter, RuleFingerprinter};
use crate::netfmt;
use crate::registry::{now_unix, Change, Device, DeviceRegistry};
use crate::storage::sqlite::SqliteStore;
use crate::storage::Store;
use crate::tui::{self, Dashboard};

/// Handle to the shared dashboard, present only in TUI mode.
type SharedDashboard = Arc<Mutex<Dashboard>>;

/// How often the in-memory registry is flushed to disk while running.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// Initialise tracing from `-v` flags, deferring to `RUST_LOG` when present.
pub fn init_tracing(verbose: u8) {
    use tracing_subscriber::{fmt, EnvFilter};
    let default = match verbose {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("lanscope={default},warn")));
    fmt().with_env_filter(filter).with_target(false).init();
}

/// Entry point invoked by the binary after CLI parsing.
pub async fn dispatch(cli: Cli) -> Result<()> {
    let db = cli.db.clone();
    match cli.command {
        Command::Run(args) => run(args, db).await,
        Command::List { json } => cmd_list(json, db),
        Command::Device { mac } => cmd_device(&mac, db),
        Command::Alerts { limit } => cmd_alerts(limit, db),
        Command::Export { format } => cmd_export(format, db),
    }
}

fn open_store(db: Option<PathBuf>) -> Result<SqliteStore> {
    let path = db.unwrap_or_else(crate::config::default_db_path);
    SqliteStore::open(&path)
}

fn resolve_config(args: &RunArgs, db: Option<PathBuf>) -> Config {
    let iface = args.interface.clone().unwrap_or_else(|| "any".to_string());
    let mut cfg = Config::new(args.mode, iface);
    if let Some(p) = db {
        cfg.db_path = p;
    }
    cfg.model_path = args.model.clone();
    cfg
}

/// `lanscope run` — start the capture pipeline (TUI by default, `--headless` for servers).
async fn run(args: RunArgs, db: Option<PathBuf>) -> Result<()> {
    let config = resolve_config(&args, db);
    warn_on_visibility(config.mode);

    let store = open_store(Some(config.db_path.clone()))?;
    let mut registry = DeviceRegistry::new();
    seed_registry(&mut registry, &store)?;
    tracing::info!(devices = registry.len(), "registry seeded from store");

    if let Some(addr) = args.metrics {
        crate::exporter::install(addr)?;
    }

    let backend = capture::select_backend(&config)?;
    let backend_name = backend.name().to_string();
    tracing::info!(backend = %backend_name, mode = config.mode.as_str(), "starting capture");

    let (tx, rx) = mpsc::channel::<CaptureEvent>(1024);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let handle = backend.spawn(tx, shutdown_rx.clone());
    spawn_signal_handler(shutdown_tx.clone());

    // TUI by default; --headless runs the loop with only logs + (later) exporter.
    let dashboard: Option<SharedDashboard> = (!args.headless).then(|| {
        Arc::new(Mutex::new(Dashboard::new(
            backend_name.clone(),
            config.mode.as_str(),
        )))
    });

    let anomaly = build_anomaly_engine(&config);

    // The capture/processing loop runs as a task so the TUI can own the main flow.
    let capture = tokio::spawn(capture_loop(
        rx,
        registry,
        store,
        shutdown_rx,
        dashboard.clone(),
        anomaly,
    ));

    if let Some(dash) = dashboard {
        let tui_shutdown = shutdown_tx.clone();
        tokio::task::spawn_blocking(move || tui::run_blocking(dash, tui_shutdown))
            .await
            .map_err(|e| Error::Other(e.into()))??;
        let _ = shutdown_tx.send(true);
    }

    // Headless: this awaits until Ctrl-C. TUI: the loop drains after the UI exits.
    let _ = capture.await;
    let _ = handle.await;
    Ok(())
}

/// Build the anomaly engine: the heuristic stack, plus the ONNX detector when
/// built with `--features ml` and a `--model` was supplied.
fn build_anomaly_engine(config: &Config) -> AnomalyEngine {
    let engine = AnomalyEngine::default_stack();
    #[cfg(feature = "ml")]
    let engine = match config.model_path.as_deref() {
        Some(path) => match crate::anomaly::onnx::OnnxDetector::from_path(path) {
            Ok(d) => {
                tracing::info!(model = %path.display(), "ML anomaly detector loaded");
                engine.with(Box::new(d))
            }
            Err(e) => {
                tracing::warn!(error = %e, "ML model not loaded; continuing with heuristics only");
                engine
            }
        },
        None => engine,
    };
    #[cfg(not(feature = "ml"))]
    if config.model_path.is_some() {
        tracing::warn!("--model ignored: rebuild with `--features ml` to enable ONNX inference");
    }
    engine
}

/// Consume capture events into the registry/store/anomaly engine until shutdown.
async fn capture_loop(
    mut rx: mpsc::Receiver<CaptureEvent>,
    mut registry: DeviceRegistry,
    store: SqliteStore,
    mut shutdown_rx: watch::Receiver<bool>,
    dashboard: Option<SharedDashboard>,
    mut anomaly: AnomalyEngine,
) -> Result<()> {
    let fingerprinter = RuleFingerprinter::new();
    let mut flush = tokio::time::interval(FLUSH_INTERVAL);
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut discoveries = 0u64;
    loop {
        tokio::select! {
            maybe = rx.recv() => match maybe {
                Some(ev) => {
                    discoveries += handle_event(
                        ev, &mut registry, &store, &fingerprinter, &mut anomaly, dashboard.as_ref(),
                    );
                }
                None => break,
            },
            _ = flush.tick() => {
                flush_all(&registry, &store);
                publish_devices(&registry, dashboard.as_ref());
                crate::exporter::set_device_count(registry.len());
            }
            res = shutdown_rx.changed() => {
                if res.is_err() || *shutdown_rx.borrow() { break; }
            }
        }
    }

    flush_all(&registry, &store);
    tracing::info!(discoveries, devices = registry.len(), "capture stopped");
    Ok(())
}

/// Mirror the current device set into the dashboard (TUI mode only).
fn publish_devices(registry: &DeviceRegistry, dashboard: Option<&SharedDashboard>) {
    if let Some(dash) = dashboard {
        let devices = registry.iter().map(|(_, d)| d.clone()).collect();
        dash.lock().unwrap().set_devices(devices);
    }
}

fn spawn_signal_handler(shutdown_tx: watch::Sender<bool>) {
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            tracing::info!("shutdown requested");
            let _ = shutdown_tx.send(true);
        }
    });
}

/// Process one capture event; returns the number of discovery observations folded in.
fn handle_event(
    ev: CaptureEvent,
    registry: &mut DeviceRegistry,
    store: &dyn Store,
    fingerprinter: &dyn Fingerprinter,
    anomaly: &mut AnomalyEngine,
    dashboard: Option<&SharedDashboard>,
) -> u64 {
    let now = now_unix();
    match ev {
        CaptureEvent::Discovery(e) => {
            let mut n = 0;
            for obs in decode_event(&e) {
                // Skip the all-zero MAC (e.g. the loopback interface) — it isn't a
                // real device, just an artifact of capturing on `lo`.
                if obs.mac == [0u8; 6] {
                    continue;
                }
                let (mac, change) = registry.observe(&obs, now);

                // Re-run the fingerprint engine now that signals changed.
                let class = registry.get(&mac).and_then(|d| fingerprinter.classify(d));
                registry.set_device_type(&mac, class.map(|c| c.device_type));

                if let Some(dev) = registry.get(&mac) {
                    if change == Change::NewDevice {
                        tracing::info!(
                            mac = %dev.mac,
                            vendor = dev.vendor.as_deref().unwrap_or("?"),
                            "new device discovered"
                        );
                        // Persist immediately so a crash before flush still records it.
                        let _ = store.upsert_device(dev);
                    }
                    let alerts = anomaly.on_device(dev, change, now);
                    emit_alerts(alerts, store, dashboard);
                }
                n += 1;
            }
            n
        }
        CaptureEvent::Flows(flows) => {
            let total: u64 = flows.iter().map(|(_, s)| s.packets).sum();
            tracing::debug!(flows = flows.len(), packets = total, "flow snapshot");
            for (key, stats) in flows {
                crate::exporter::record_flow(stats.packets, stats.bytes);
                registry.apply_flow(&key, &stats, now);
                let alerts = anomaly.on_flow(&key, &stats, now);
                emit_alerts(alerts, store, dashboard);
            }
            0
        }
    }
}

/// Log, persist, and (in TUI mode) surface a batch of alerts.
fn emit_alerts(alerts: Vec<Alert>, store: &dyn Store, dashboard: Option<&SharedDashboard>) {
    for alert in alerts {
        match alert.severity {
            Severity::Info => tracing::info!(kind = %alert.kind, "{}", alert.message),
            Severity::Warning => tracing::warn!(kind = %alert.kind, "{}", alert.message),
            Severity::Critical => tracing::error!(kind = %alert.kind, "{}", alert.message),
        }
        if let Err(e) = store.record_alert(&alert) {
            tracing::warn!(error = %e, "failed to persist alert");
        }
        crate::exporter::record_alert(alert.severity);
        if let Some(dash) = dashboard {
            dash.lock().unwrap().push_alert(alert);
        }
    }
}

fn seed_registry(registry: &mut DeviceRegistry, store: &dyn Store) -> Result<()> {
    for dev in store.load_devices()? {
        if let Some(mac) = netfmt::parse_mac(&dev.mac) {
            registry.load(mac, dev);
        }
    }
    Ok(())
}

fn flush_all(registry: &DeviceRegistry, store: &dyn Store) {
    for (_, dev) in registry.iter() {
        if let Err(e) = store.upsert_device(dev) {
            tracing::warn!(error = %e, mac = %dev.mac, "failed to persist device");
        }
    }
}

/// Emit a one-time honesty notice about what the chosen mode can actually see.
fn warn_on_visibility(mode: CaptureMode) {
    if !mode.sees_whole_lan() {
        tracing::warn!(
            "host mode sees only this host's traffic + broadcast/multicast; \
             run on a gateway or SPAN port to fingerprint every device's flows"
        );
    }
}

// --- read-only commands ---

fn cmd_list(json: bool, db: Option<PathBuf>) -> Result<()> {
    let store = open_store(db)?;
    let mut devices = store.load_devices()?;
    devices.sort_by_key(|d| std::cmp::Reverse(d.last_seen));

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&devices).unwrap_or_default()
        );
        return Ok(());
    }
    if devices.is_empty() {
        println!("No devices yet — run `lanscope run` to start discovery.");
        return Ok(());
    }
    print_device_table(&devices);
    Ok(())
}

fn print_device_table(devices: &[Device]) {
    println!(
        "{:<18} {:<26} {:<18} {:<16} {:>5} {:<19}",
        "MAC", "VENDOR", "HOSTNAME", "IP", "SVCS", "LAST SEEN"
    );
    println!("{}", "-".repeat(104));
    for d in devices {
        println!(
            "{:<18} {:<26} {:<18} {:<16} {:>5} {:<19}",
            d.mac,
            truncate(d.vendor.as_deref().unwrap_or("-"), 26),
            truncate(d.hostname.as_deref().unwrap_or("-"), 18),
            d.ips.last().map(String::as_str).unwrap_or("-"),
            d.services.len(),
            netfmt::fmt_ts(d.last_seen),
        );
    }
    println!("\n{} device(s).", devices.len());
}

fn cmd_device(mac: &str, db: Option<PathBuf>) -> Result<()> {
    let store = open_store(db)?;
    let want = mac.to_ascii_lowercase();
    let Some(d) = store.load_devices()?.into_iter().find(|d| d.mac == want) else {
        println!("No record for {mac}.");
        return Ok(());
    };
    println!("Device {}", d.mac);
    println!("  label:        {}", d.label());
    println!("  vendor:       {}", d.vendor.as_deref().unwrap_or("-"));
    println!("  hostname:     {}", d.hostname.as_deref().unwrap_or("-"));
    println!(
        "  device type:  {}",
        d.device_type.as_deref().unwrap_or("(not yet inferred)")
    );
    println!(
        "  ips:          {}",
        if d.ips.is_empty() {
            "-".into()
        } else {
            d.ips.join(", ")
        }
    );
    println!(
        "  dhcp fp:      {}",
        d.dhcp_fingerprint.as_deref().unwrap_or("-")
    );
    println!(
        "  vendor class: {}",
        d.dhcp_vendor_class.as_deref().unwrap_or("-")
    );
    println!("  traffic:      {} pkts / {} bytes", d.packets, d.bytes);
    println!("  first seen:   {}", netfmt::fmt_ts(d.first_seen));
    println!("  last seen:    {}", netfmt::fmt_ts(d.last_seen));
    if d.services.is_empty() {
        println!("  services:     -");
    } else {
        println!("  services:");
        for s in &d.services {
            println!("    - {s}");
        }
    }
    Ok(())
}

fn cmd_alerts(limit: usize, db: Option<PathBuf>) -> Result<()> {
    let store = open_store(db)?;
    let alerts = store.recent_alerts(limit)?;
    if alerts.is_empty() {
        println!("No alerts yet.");
        return Ok(());
    }
    for a in alerts {
        println!(
            "{} [{}] {} {} — {}",
            netfmt::fmt_ts(a.ts),
            a.severity.as_str().to_uppercase(),
            a.mac.as_deref().unwrap_or("-"),
            a.kind,
            a.message
        );
    }
    Ok(())
}

fn cmd_export(format: ExportFormat, db: Option<PathBuf>) -> Result<()> {
    let store = open_store(db)?;
    let devices = store.load_devices()?;
    match format {
        ExportFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&devices).unwrap_or_default()
            );
        }
        ExportFormat::Csv => {
            println!("mac,vendor,hostname,ip,services,packets,bytes,first_seen,last_seen");
            for d in devices {
                println!(
                    "{},{},{},{},{},{},{},{},{}",
                    d.mac,
                    csv(d.vendor.as_deref()),
                    csv(d.hostname.as_deref()),
                    d.ips.last().map(String::as_str).unwrap_or(""),
                    d.services.len(),
                    d.packets,
                    d.bytes,
                    d.first_seen,
                    d.last_seen,
                );
            }
        }
    }
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max.saturating_sub(1)).collect();
        t.push('…');
        t
    }
}

/// Escape a CSV field minimally (quote if it contains a comma/quote).
fn csv(v: Option<&str>) -> String {
    let s = v.unwrap_or("");
    if s.contains(',') || s.contains('"') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
