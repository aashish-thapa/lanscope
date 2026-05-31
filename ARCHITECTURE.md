# lanscope architecture

A map of how the pieces fit, the design decisions behind them, and the
hard-won lessons (especially eBPF). For usage see [README.md](README.md); for
the ML pipeline see [ml/README.md](ml/README.md).

## Pipeline

```
CaptureBackend ─▶ decode ─▶ DeviceRegistry ─▶ Fingerprinter ─▶ AnomalyEngine
  (eBPF |          (ARP/      (keyed by MAC)     (rules)         (heuristics
   portable)        DHCP/          │                              + ONNX)
                    mDNS/SSDP)     └────────▶ Store (SQLite) ◀────────┘
                                                  │
                                   Dashboard ─▶ Ratatui TUI / Prometheus exporter
```

Each arrow is a trait seam, so every stage is swappable and unit-testable in
isolation. The pipeline depends on *traits*, never on concrete I/O — which is
what lets the whole agent build and test on stable Rust with no eBPF toolchain.

## Crates

| Crate | Responsibility |
|---|---|
| `lanscope-common` | `#[repr(C)]` POD types crossing the kernel/user boundary (`FlowKey`, `FlowStats`, `Event`). `no_std`; the `aya-pod` feature adds `aya::Pod` impls for userspace. |
| `lanscope-ebpf` | The XDP program. Targets `bpfel-unknown-none`, built out-of-band; excluded from the workspace so a stock `cargo build` never touches it. |
| `lanscope` | The userspace agent — everything below. |
| `xtask` | `cargo xtask build-ebpf` convenience wrapper. |

## Userspace modules (`lanscope/src`)

- `capture/` — **the key seam.** `CaptureBackend` trait + `CaptureEvent`. `ebpf.rs`
  (feature `ebpf`) loads/attaches the XDP program and bridges its maps; `mock.rs`
  is the portable backend (currently a synthetic replay source — a real
  `AF_PACKET` reader is the planned drop-in).
- `decode/` — pure `&[u8] → Vec<Signal>` protocol decoders (ARP/DHCP/mDNS/SSDP),
  tested against byte fixtures.
- `registry/` — `DeviceRegistry` keyed by MAC; folds observations + flow snapshots
  into `Device` records. Pure state, no I/O.
- `fingerprint/` — `Fingerprinter` trait, OUI table, and a data-driven rule engine
  (strongest-confidence match wins).
- `anomaly/` — `Detector` trait + `Engine`; heuristic detectors (new device, port
  scan, volume spike) and the optional `onnx.rs` ML detector.
- `features.rs` — the flow feature vector; the **single source of truth** shared
  with the Python training pipeline.
- `storage/` — `Store` trait + bundled-SQLite implementation.
- `exporter.rs` — Prometheus `/metrics` (feature-free; the `metrics` macros are
  no-ops until installed).
- `tui/` — Ratatui dashboard, run on a blocking thread.
- `app.rs` — composition root: wires concrete implementations and runs the loop.

## Capture modes & visibility

eBPF/XDP only sees traffic the host's NIC sees. On a switched LAN that's the
host's own traffic + broadcast/multicast — so:

- `gateway` / `span` — host routes or mirrors all device traffic → full per-device
  flow features + ML.
- `host` — discovery (ARP/DHCP/mDNS/SSDP, all broadcast/multicast) + own flows.

The agent logs an explicit notice when a mode can't see whole-LAN traffic.

## Kernel/userspace split

The eBPF side does only cheap hot-path work: flow counters in a `HashMap`,
constant-offset header parsing, and copying interesting packets into a `RingBuf`.
All deep protocol decode happens in userspace. Flows are drained-and-removed each
interval, so every snapshot is the delta since the last.

### eBPF verifier lessons (the non-obvious bits)

1. The eBPF crate's `[profile.dev]` must set `debug-assertions = false` (and
   `overflow-checks = false`). Otherwise the compiler inserts
   `panic_misaligned_pointer_dereference`/panic stubs — non-terminating cold
   blocks that make the verifier reject with *"last insn is not an exit or jmp."*
2. `#[inline(always)]` every helper so there's one program, no bpf-to-bpf
   subprograms to satisfy.
3. For any **variable-length or variable-offset** packet read, use
   `bpf_xdp_load_bytes(ctx, off, buf, len)` into a stack/ring buffer instead of
   direct packet access — the verifier can't track packet-pointer ranges through
   per-byte loops at a variable offset. Constant-offset direct reads are fine.

## Build

- Userspace: stable Rust, `cargo build` (no eBPF/ML toolchain needed).
- eBPF backend: `--features ebpf`; `build.rs` compiles `lanscope-ebpf` with the
  nightly toolchain it pins, via `bpf-linker`, staging the object in `OUT_DIR`.
- ML: `--features ml` pulls ONNX Runtime via `ort`; `--model` supplies the `.onnx`.

Loading XDP needs `CAP_BPF` + `CAP_NET_ADMIN` (or root); without them the agent
falls back to the portable backend.
