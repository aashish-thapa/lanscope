#!/usr/bin/env python3
"""Print the feature vector for a reference flow.

Eyeball this against the Rust golden test in `lanscope/src/features.rs`
(`golden_vector`) to confirm the two extractors agree on the features the
dataset can represent. Note the documented min_len/max_len caveat (see README):
conn.log has no per-packet sizes, so those are approximated here.
"""

from features import FEATURE_NAMES, extract_row

# A 2-second, 42-packet / 5120-byte TCP flow to port 443 — mirrors the Rust
# golden test's inputs (history "SA..." => 1 SYN-ish, plenty of ACKs).
reference = {
    "duration": 2.0,
    "orig_pkts": 42,
    "resp_pkts": 0,
    "orig_bytes": 5120,
    "resp_bytes": 0,
    "history": "S" + "A" * 40,
    "proto": "tcp",
    "id.resp_p": 443,
}

if __name__ == "__main__":
    vec = extract_row(reference)
    width = max(len(n) for n in FEATURE_NAMES)
    for name, value in zip(FEATURE_NAMES, vec):
        print(f"{name:<{width}}  {value}")
