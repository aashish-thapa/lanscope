# lanscope ML pipeline (IoT-23 → ONNX)

Offline training for lanscope's optional flow classifier. This is **scaffolding**:
it is not run as part of the Rust build. You run it when you want a real model,
then point the agent at the resulting `model.onnx`.

```
IoT-23 labeled flows ──▶ features.py ──▶ RandomForest ──▶ to_onnx(zipmap=False) ──▶ model.onnx
                          (shared spec)                                              │
                                                                                     ▼
                              lanscope run --model model.onnx   (build: --features ml)
```

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Get the Stratosphere "IoT-23 lighter" labeled CSVs (small; full pcaps are ~GBs):
#   https://www.stratosphereips.org/datasets-iot23
python train.py --input iot23_labeled.csv --out model.onnx

# Then, in the repo root:
cargo build --release --features ml
sudo ./target/release/lanscope run --mode gateway --interface eth0 --model ml/model.onnx
```

If the model is missing or the build lacks `--features ml`, the agent logs a notice
and keeps running on the heuristic detectors — ML is purely additive.

## The feature contract (read this)

`features.py::FEATURE_NAMES` and `lanscope/src/features.rs::FEATURE_NAMES` **must
match exactly** — same names, order, and meaning — or the model mispredicts. The
13 features are derived from a single unidirectional flow.

**Honest caveat — `min_len` / `max_len`.** At runtime these come from the eBPF data
path (real per-packet L3 lengths). IoT-23's `conn.log` is a *flow summary* and has
no per-packet sizes, so `train.py` approximates both as the mean packet length.
A model trained this way sees flat min/max at train time but real spread at
runtime → those two features are effectively weak. Two ways to get true parity:

1. **Drop them** from both `features.py` and `features.rs` (retrain, edit the Rust
   `FEATURE_NAMES`/`extract` to 11 features) — simplest path to faithful features.
2. **Train from packet-level data** (pcaps, or capture your own labeled flows with
   lanscope's eBPF backend) so `min_len`/`max_len` are exact on both sides.

`parity.py` prints the vector for a reference flow so you can eyeball it against
the Rust golden test (`features.rs::golden_vector`).

## ONNX I/O expected by the Rust side

- Input: float tensor `[None, 13]` named `input`.
- Output: a probability tensor whose **last column is P(malicious)**. `train.py`
  passes `zipmap=False` so probabilities are a plain `[N, 2]` tensor rather than
  skl2onnx's default sequence-of-maps (which the Rust reader can't consume).
