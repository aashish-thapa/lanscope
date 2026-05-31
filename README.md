# lanscope

**Passive eBPF-powered IoT device fingerprinting & anomaly detection for your LAN.**

`lanscope` watches your network, figures out *what* every device is (vendor, type,
hostname, services) from the metadata it leaks — ARP, DHCP, mDNS/Bonjour, SSDP/UPnP —
and flags devices behaving anomalously. The high-performance capture path is built in
the kernel with **eBPF** (via [aya](https://aya-rs.dev), Rust-native eBPF); everything
else is safe userspace Rust with a Ratatui TUI.

> **Status:** early. M0 (skeleton) and M1 (passive discovery + device registry) are
> implemented and tested. The eBPF capture backend, fingerprint engine, anomaly
> heuristics, TUI, Prometheus exporter, and ONNX model are on the roadmap below.

---

## Where it sees traffic (read this first)

On a **switched** network, a host's NIC only sees traffic addressed *to itself* plus
broadcast/multicast. That shapes everything `lanscope` can do, so it runs in one of
three modes:

| Mode | Placement | Visibility |
|---|---|---|
| `gateway` | the router / a Pi inline | **all** device traffic → full flow features + ML |
| `span` | a switch SPAN/mirror port | same as gateway, not inline (no forwarding risk) |
| `host` | any laptop/desktop | this host's traffic **+ broadcast/multicast discovery** |

Discovery (ARP/DHCP/mDNS/SSDP) works in **every** mode — that's how `host` mode still
maps your whole network. Per-device *flow* analysis and ML need `gateway`/`span`.
`lanscope` prints an explicit notice when a mode can't see whole-LAN traffic.

---

## Architecture

```
CaptureBackend → decode → DeviceRegistry → Fingerprinter → AnomalyDetector
   (eBPF |              (ARP/DHCP/         (keyed by MAC)        │
    portable)            mDNS/SSDP)              │              │
                                                 └──► Store ◄────┘   → TUI / Prometheus
```

Everything hangs off trait seams so each stage is swappable and unit-testable:

- **`CaptureBackend`** — the key Dependency-Inversion boundary. The pipeline never
  touches aya directly; the in-kernel eBPF backend (feature `ebpf`) and a portable
  backend implement the same trait, so the whole agent builds and tests on **stable
  Rust with no eBPF toolchain**.
- **`Store`** — SQLite (bundled) in production, in-memory fake in tests.
- Decoders are pure `&[u8] → Vec<Signal>` functions, tested against byte fixtures.

### Workspace

| Crate | Role |
|---|---|
| `lanscope-common` | `#[repr(C)]` POD types shared across the kernel/userspace boundary (`no_std`). |
| `lanscope` | userspace agent: capture, decode, registry, fingerprint, anomaly, storage, CLI/TUI. |
| `lanscope-ebpf` | the eBPF programs (XDP + TC), built out-of-band (targets `bpfel-unknown-none`). |
| `xtask` | builds the eBPF crate (`cargo xtask build-ebpf`). |

---

## Build & run

The userspace tool builds on **stable Rust**, no special toolchain:

```bash
cargo build --release
cargo test                       # unit tests for decoders, registry, storage

# Passively discover devices (host mode; portable backend if eBPF not built):
cargo run -- run --mode host

# One-shot views:
cargo run -- list                # device table
cargo run -- list --json
cargo run -- device aa:bb:cc:dd:ee:ff
cargo run -- alerts
cargo run -- export --format csv
```

The database lives at `$XDG_DATA_HOME/lanscope/lanscope.db` (override with `--db`).

### Enabling the eBPF backend (gateway/span flow analysis)

Requires the eBPF toolchain (not needed for the core tool):

```bash
cargo install bpf-linker          # needs LLVM (Arch: pacman -S llvm clang)
rustup toolchain install nightly  # for -Z build-std
cargo xtask build-ebpf            # compile the kernel object
cargo build --features ebpf       # link the in-kernel backend in
sudo ./target/debug/lanscope run --mode gateway --interface eth0
```

Loading XDP/TC needs `CAP_BPF` + `CAP_NET_ADMIN` (or root).

### Optional ML scoring

```bash
cargo build --features ml         # pulls ONNX Runtime; anomaly model is optional
```

---

## Roadmap

- [x] **M0** — workspace skeleton, CLI, capture trait, tracing
- [x] **M1** — passive discovery (ARP/DHCP/mDNS/SSDP), device registry, OUI vendor lookup, SQLite, `list`
- [x] **M2** — eBPF XDP flow accounting (BPF `HashMap` + ring-buffer events), verifier-validated on a live interface
- [x] **M3** — fingerprint engine (OUI + DHCP + mDNS/SSDP + traffic → device type)
- [x] **M4** — anomaly heuristics (new device / port scan / volume spike) + Ratatui TUI
- [x] **M5** — Prometheus exporter (`run --metrics <addr>`) + headless mode
- [x] **M6** — ONNX inference slot (`--features ml`, `--model`) with graceful no-model degrade; IoT-23 → ONNX training pipeline in `ml/` (run when you want a model)

---

## Ethics

`lanscope` is a defensive / home-lab tool. Only run it on networks you own or are
authorised to monitor. Gateway/SPAN placement exposes plaintext metadata of all
devices — treat the database accordingly.

## License

MIT OR Apache-2.0.
