# lanscope task runner — run `just` to list recipes.
# Most recipes pass extra args through, e.g. `just run -i wlan0 --mode gateway`.

# Default interface for the privileged eBPF recipes.
iface := env_var_or_default("LANSCOPE_IFACE", "eth0")
# Default Prometheus listen address.
metrics_addr := env_var_or_default("LANSCOPE_METRICS", "0.0.0.0:9184")

# List available recipes.
default:
    @just --list

# --- build ---------------------------------------------------------------

# Build the userspace agent (stable Rust, no eBPF toolchain needed).
build:
    cargo build

# Optimized release build.
release:
    cargo build --release

# Compile the eBPF kernel object (nightly + bpf-linker).
build-ebpf:
    cargo xtask build-ebpf

# Build the agent with the in-kernel eBPF backend linked in.
build-with-ebpf:
    cargo build --features ebpf

# Build with the optional ONNX ML detector (pulls ONNX Runtime).
build-ml:
    cargo build --features ml

# Train the IoT-23 classifier → ONNX (needs Python deps + dataset). See ml/README.md.
train input out="model.onnx":
    cd ml && python3 train.py --input {{input}} --out {{out}}

# --- quality gate --------------------------------------------------------

# Run the unit tests.
test:
    cargo test

# Lint (deny warnings).
clippy:
    cargo clippy --all-targets -- -D warnings

# Lint including the eBPF feature.
clippy-ebpf:
    cargo clippy --all-targets --features ebpf -- -D warnings

# Format the workspace.
fmt:
    cargo fmt

# Check formatting without modifying.
fmt-check:
    cargo fmt --check

# Full pre-commit gate: format check + lint + tests.
check: fmt-check clippy test

# --- run (portable backend, no privileges) -------------------------------

# Run the live TUI (host mode by default). Extra args passed through.
run *args:
    cargo run -- run {{args}}

# Run headless (logs only, no TUI). Extra args passed through.
headless *args:
    cargo run -- run --headless {{args}}

# Run headless with the Prometheus exporter; scrape at /metrics.
metrics *args:
    cargo run -- run --headless --metrics {{metrics_addr}} {{args}}

# --- run (eBPF backend, needs root) --------------------------------------

# Run the real eBPF/XDP backend on {{iface}} in gateway mode (sudo).
run-ebpf mode="gateway": build-with-ebpf
    sudo ./target/debug/lanscope run --mode {{mode}} --interface {{iface}}

# Load the eBPF program on loopback to confirm the verifier accepts it (sudo).
verify-ebpf: build-with-ebpf
    sudo timeout 8 sh -c './target/debug/lanscope -v run --mode host --interface lo --headless & P=$!; sleep 1; ping -c 5 127.0.0.1 >/dev/null 2>&1; curl -s localhost >/dev/null 2>&1; sleep 3; kill $P 2>/dev/null; wait $P'

# --- read-only views -----------------------------------------------------

# Print the device table.
list:
    cargo run -- list

# Print the device table as JSON.
list-json:
    cargo run -- list --json

# Show detail for one device, e.g. `just device aa:bb:cc:dd:ee:ff`.
device mac:
    cargo run -- device {{mac}}

# Show recent anomaly alerts.
alerts:
    cargo run -- alerts

# Export the database (csv|json), e.g. `just export csv`.
export fmt="json":
    cargo run -- export --format {{fmt}}

# --- housekeeping --------------------------------------------------------

# Remove build artifacts (workspace + eBPF crate).
clean:
    cargo clean
    cd lanscope-ebpf && cargo clean
