#!/usr/bin/env python3
"""Train a flow classifier on IoT-23 and export it to ONNX for lanscope.

Pipeline:  IoT-23 labeled conn flows  ->  feature matrix (features.py)
           ->  RandomForest  ->  ONNX (zipmap=False)  ->  model.onnx

The model is exported with a `[1, FEATURE_COUNT]` float input named `input` and
a probability tensor output whose LAST column is P(malicious) — exactly what
`lanscope/src/anomaly/onnx.rs` expects.

Usage:
    python train.py --input iot23_labeled.csv --out model.onnx

Input CSV: a flattened IoT-23 conn.log with Zeek columns (duration, orig_pkts,
resp_pkts, orig_bytes, resp_bytes, history, proto, id.resp_p) plus a `label`
column ("Benign"/"Malicious", case-insensitive; anything not benign => malicious).
The Stratosphere "IoT-23 lighter" CSVs work well and are far smaller than the
full pcaps.
"""

from __future__ import annotations

import argparse
import sys

import numpy as np
import pandas as pd

from features import FEATURE_COUNT, FEATURE_NAMES, extract_row


def load_xy(csv_path: str) -> tuple[np.ndarray, np.ndarray]:
    df = pd.read_csv(csv_path)
    rows = df.to_dict(orient="records")
    X = np.array([extract_row(r) for r in rows], dtype=np.float32)

    label_col = next((c for c in df.columns if c.lower() == "label"), None)
    if label_col is None:
        sys.exit("input CSV needs a `label` column (Benign/Malicious)")
    y = np.array(
        [0 if str(v).strip().lower() == "benign" else 1 for v in df[label_col]],
        dtype=np.int64,
    )
    return X, y


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True, help="IoT-23 labeled CSV")
    ap.add_argument("--out", default="model.onnx", help="output ONNX path")
    ap.add_argument("--trees", type=int, default=100)
    args = ap.parse_args()

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split
    from skl2onnx import to_onnx
    from skl2onnx.common.data_types import FloatTensorType

    X, y = load_xy(args.input)
    print(f"loaded {len(X)} flows, {FEATURE_COUNT} features: {FEATURE_NAMES}")

    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=args.trees, n_jobs=-1, random_state=42)
    clf.fit(X_tr, y_tr)
    print(classification_report(y_te, clf.predict(X_te), digits=3))

    # zipmap=False => probabilities come out as a plain float tensor [N, 2],
    # so the Rust side can read the last column as P(malicious).
    onx = to_onnx(
        clf,
        initial_types=[("input", FloatTensorType([None, FEATURE_COUNT]))],
        options={id(clf): {"zipmap": False}},
        target_opset=17,
    )
    with open(args.out, "wb") as f:
        f.write(onx.SerializeToString())
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
