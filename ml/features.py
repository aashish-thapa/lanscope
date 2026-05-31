"""Feature spec for lanscope's flow classifier.

This MUST stay byte-for-byte in lockstep with the Rust runtime extractor in
`lanscope/src/features.rs` (`FEATURE_NAMES` / `extract`). Same names, same order,
same meaning — otherwise the model mispredicts at runtime.
"""

from __future__ import annotations

# Order and names mirror lanscope/src/features.rs::FEATURE_NAMES exactly.
FEATURE_NAMES = [
    "duration_secs",
    "packets",
    "bytes",
    "bytes_per_sec",
    "mean_packet_len",
    "min_len",
    "max_len",
    "syn",
    "fin",
    "rst",
    "ack",
    "protocol",
    "dst_port",
]

FEATURE_COUNT = len(FEATURE_NAMES)

# IANA protocol numbers, matching lanscope_common::flow::Protocol.
_PROTO = {"icmp": 1, "tcp": 6, "udp": 17}


def proto_to_num(proto: str) -> int:
    return _PROTO.get(str(proto).strip().lower(), 255)


def count_flags(history: str) -> dict[str, int]:
    """Approximate TCP flag counts from a Zeek conn.log `history` string.

    Zeek encodes flags as letters (S=SYN, F=FIN, R=RST, originator uppercase /
    responder lowercase, etc.). We count case-insensitively — a coarse proxy for
    the per-flag counters the eBPF data path accumulates at runtime.
    """
    h = str(history or "")
    low = h.lower()
    return {
        "syn": low.count("s"),
        "fin": low.count("f"),
        "rst": low.count("r"),
        "ack": low.count("a"),
    }


def extract_row(row: dict) -> list[float]:
    """Build a feature vector (in FEATURE_NAMES order) from one IoT-23 conn record.

    `row` keys are Zeek conn.log fields. Caller is responsible for column mapping
    (see train.py). Fields absent in conn.log (min/max packet length) are
    approximated from the mean — a documented limitation of training on
    flow-summary data rather than per-packet captures.
    """
    duration = float(row.get("duration", 0.0) or 0.0)
    orig_pkts = float(row.get("orig_pkts", 0.0) or 0.0)
    resp_pkts = float(row.get("resp_pkts", 0.0) or 0.0)
    orig_bytes = float(row.get("orig_bytes", 0.0) or 0.0)
    resp_bytes = float(row.get("resp_bytes", 0.0) or 0.0)

    packets = orig_pkts + resp_pkts
    total_bytes = orig_bytes + resp_bytes
    bytes_per_sec = total_bytes / duration if duration > 0 else total_bytes
    mean_len = total_bytes / packets if packets > 0 else 0.0

    flags = count_flags(row.get("history", ""))

    return [
        duration,                                   # duration_secs
        packets,                                    # packets
        total_bytes,                                # bytes
        bytes_per_sec,                              # bytes_per_sec
        mean_len,                                   # mean_packet_len
        mean_len,                                   # min_len  (approx; not in conn.log)
        mean_len,                                   # max_len  (approx; not in conn.log)
        float(flags["syn"]),                        # syn
        float(flags["fin"]),                        # fin
        float(flags["rst"]),                        # rst
        float(flags["ack"]),                        # ack
        float(proto_to_num(row.get("proto", ""))),  # protocol
        float(row.get("id.resp_p", 0) or 0),        # dst_port
    ]
