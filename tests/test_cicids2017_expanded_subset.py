import json
import subprocess
import sys
from pathlib import Path

import pandas as pd


ROOT = Path(__file__).resolve().parents[1]
TARGET_LABELS = [
    "BENIGN",
    "DDoS",
    "DoS Hulk",
    "DoS GoldenEye",
    "DoS slowloris",
    "DoS Slowhttptest",
    "PortScan",
    "FTP-Patator",
    "SSH-Patator",
    "Heartbleed",
    "Web Attack Brute Force",
    "Web Attack XSS",
    "Web Attack Sql Injection",
]


def _row(label, port):
    return {
        "Destination Port": port,
        "Flow Duration": 1000 + port,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 5,
        "Total Length of Fwd Packets": 500,
        "Total Length of Bwd Packets": 250,
        "Fwd Packet Length Mean": 50.0,
        "Bwd Packet Length Mean": 25.0,
        "Flow Bytes/s": 1000.0,
        "Flow Packets/s": 30.0,
        "Label": label,
    }


def test_make_cicids2017_expanded_summary_structure(tmp_path):
    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    rows = []
    for idx, label in enumerate(TARGET_LABELS):
        for offset in range(3):
            rows.append(_row(label, 1000 + idx * 10 + offset))
    pd.DataFrame(rows).to_csv(raw_dir / "synthetic_cicids.csv", index=False)

    out_csv = tmp_path / "cicids2017_expanded_scenario_ordered.csv"
    summary_json = tmp_path / "cicids2017_expanded_summary.json"
    subprocess.check_call(
        [
            sys.executable,
            "scripts/make_cicids2017_subset.py",
            "--raw-dir",
            str(raw_dir),
            "--rows-per-class",
            "2",
            "--out",
            str(out_csv),
            "--summary-out",
            str(summary_json),
        ],
        cwd=str(ROOT),
    )

    assert out_csv.exists()
    assert summary_json.exists()
    summary = json.loads(summary_json.read_text(encoding="utf-8"))
    assert summary["scenario"] == "cicids2017_expanded"
    assert summary["rows_per_class"] == 2
    assert summary["target_labels"] == TARGET_LABELS
    assert summary["ordered_by_stage"] is True
    assert summary["missing_labels"] == []
    assert summary["partial_labels"] == []
    assert summary["total_rows"] == len(TARGET_LABELS) * 2
    for label in TARGET_LABELS:
        assert summary["label_counts"][label] == 2

    out = pd.read_csv(out_csv)
    assert out["Label"].tolist() == [label for label in TARGET_LABELS for _ in range(2)]
