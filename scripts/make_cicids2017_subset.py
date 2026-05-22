from pathlib import Path
import argparse
import json

import pandas as pd


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

KEEP_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Mean",
    "Bwd Packet Length Mean",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Label",
]

COLUMN_ALIASES = {
    "Dst Port": "Destination Port",
    "Destination Port": "Destination Port",
    "Tot Fwd Pkts": "Total Fwd Packets",
    "Total Fwd Packets": "Total Fwd Packets",
    "Tot Bwd Pkts": "Total Backward Packets",
    "Total Backward Packets": "Total Backward Packets",
    "TotLen Fwd Pkts": "Total Length of Fwd Packets",
    "Total Length of Fwd Packets": "Total Length of Fwd Packets",
    "TotLen Bwd Pkts": "Total Length of Bwd Packets",
    "Total Length of Bwd Packets": "Total Length of Bwd Packets",
    "Fwd Pkt Len Mean": "Fwd Packet Length Mean",
    "Fwd Packet Length Mean": "Fwd Packet Length Mean",
    "Bwd Pkt Len Mean": "Bwd Packet Length Mean",
    "Bwd Packet Length Mean": "Bwd Packet Length Mean",
    "Flow Byts/s": "Flow Bytes/s",
    "Flow Bytes/s": "Flow Bytes/s",
    "Flow Pkts/s": "Flow Packets/s",
    "Flow Packets/s": "Flow Packets/s",
    "Label": "Label",
}

LABEL_ALIASES = {
    "Web Attack \ufffd Brute Force": "Web Attack Brute Force",
    "Web Attack � Brute Force": "Web Attack Brute Force",
    "Web Attack-Brute Force": "Web Attack Brute Force",
    "Web Attack Brute Force": "Web Attack Brute Force",
    "Web Attack \ufffd XSS": "Web Attack XSS",
    "Web Attack � XSS": "Web Attack XSS",
    "Web Attack-XSS": "Web Attack XSS",
    "Web Attack XSS": "Web Attack XSS",
    "Web Attack \ufffd Sql Injection": "Web Attack Sql Injection",
    "Web Attack � Sql Injection": "Web Attack Sql Injection",
    "Web Attack-Sql Injection": "Web Attack Sql Injection",
    "Web Attack Sql Injection": "Web Attack Sql Injection",
}


def normalize_label(value: str) -> str:
    label = str(value).strip()
    return LABEL_ALIASES.get(label, label)


def iter_raw_csvs(raw_dir: Path):
    return sorted(path for path in raw_dir.glob("*.csv") if path.is_file())


def normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    renamed = {}
    for col in df.columns:
        clean = str(col).strip()
        renamed[col] = COLUMN_ALIASES.get(clean, clean)
    return df.rename(columns=renamed)


def clean_chunk(chunk: pd.DataFrame) -> pd.DataFrame:
    chunk = normalize_columns(chunk)
    if "Label" not in chunk.columns:
        return pd.DataFrame(columns=KEEP_COLUMNS)
    for col in KEEP_COLUMNS:
        if col not in chunk.columns:
            chunk[col] = 0.0 if col != "Label" else "UNKNOWN"
    chunk = chunk[KEEP_COLUMNS].copy()
    chunk["Label"] = chunk["Label"].map(normalize_label)
    chunk = chunk.replace([float("inf"), float("-inf")], pd.NA)
    return chunk.dropna(subset=KEEP_COLUMNS)


def collect_balanced_rows(raw_dir: Path, rows_per_class: int, chunk_size: int):
    buffers = {label: [] for label in TARGET_LABELS}
    source_files = {label: [] for label in TARGET_LABELS}
    csv_files = list(iter_raw_csvs(raw_dir))
    target_set = set(TARGET_LABELS)

    for csv_path in csv_files:
        try:
            reader = pd.read_csv(csv_path, chunksize=chunk_size)
            for chunk in reader:
                cleaned = clean_chunk(chunk)
                if cleaned.empty:
                    continue
                for label in TARGET_LABELS:
                    current = sum(len(part) for part in buffers[label])
                    remaining = rows_per_class - current
                    if remaining <= 0:
                        continue
                    part = cleaned[cleaned["Label"] == label]
                    if part.empty:
                        continue
                    selected = part.head(remaining).copy()
                    buffers[label].append(selected)
                    if str(csv_path) not in source_files[label]:
                        source_files[label].append(str(csv_path))
                if all(sum(len(part) for part in buffers[label]) >= rows_per_class for label in target_set):
                    break
        except Exception as exc:
            print("[WARN] failed to read %s: %s" % (csv_path, exc))
        if all(sum(len(part) for part in buffers[label]) >= rows_per_class for label in target_set):
            break

    ordered_parts = []
    label_counts = {}
    for label in TARGET_LABELS:
        if buffers[label]:
            combined = pd.concat(buffers[label], ignore_index=True).head(rows_per_class)
        else:
            combined = pd.DataFrame(columns=KEEP_COLUMNS)
        label_counts[label] = int(len(combined))
        if not combined.empty:
            ordered_parts.append(combined)

    if ordered_parts:
        out = pd.concat(ordered_parts, ignore_index=True)
    else:
        out = pd.DataFrame(columns=KEEP_COLUMNS)
    return out, label_counts, source_files, [str(path) for path in csv_files]


def write_summary(path: Path, out_csv: Path, rows_per_class: int, label_counts, source_files, scanned_files):
    missing_labels = [label for label, count in label_counts.items() if count == 0]
    partial_labels = [label for label, count in label_counts.items() if 0 < count < rows_per_class]
    summary = {
        "scenario": "cicids2017_expanded",
        "output_csv": str(out_csv),
        "rows_per_class": int(rows_per_class),
        "target_labels": TARGET_LABELS,
        "label_counts": label_counts,
        "total_rows": int(sum(label_counts.values())),
        "missing_labels": missing_labels,
        "partial_labels": partial_labels,
        "ordered_by_stage": True,
        "source_files_by_label": source_files,
        "scanned_files": scanned_files,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description="Build a balanced ordered expanded CICIDS2017 dynamic-defense scenario.")
    parser.add_argument("--raw-dir", required=True, help="Directory containing original CICIDS2017 CSV files")
    parser.add_argument("--rows-per-class", type=int, default=200)
    parser.add_argument("--chunk-size", type=int, default=50000)
    parser.add_argument("--out", default="data/cicids2017_subset/cicids2017_expanded_scenario_ordered.csv")
    parser.add_argument("--summary-out", default="data/cicids2017_subset/cicids2017_expanded_summary.json")
    # Backward-compatible aliases used by the older 3-attack subset builder.
    parser.add_argument("--per-attack", type=int, default=None, help=argparse.SUPPRESS)
    parser.add_argument("--benign", type=int, default=None, help=argparse.SUPPRESS)
    args = parser.parse_args()

    rows_per_class = args.rows_per_class
    if args.per_attack is not None:
        rows_per_class = args.per_attack

    raw_dir = Path(args.raw_dir)
    out_path = Path(args.out)
    summary_path = Path(args.summary_out)

    out, label_counts, source_files, scanned_files = collect_balanced_rows(
        raw_dir=raw_dir,
        rows_per_class=rows_per_class,
        chunk_size=args.chunk_size,
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_path, index=False)
    summary = write_summary(summary_path, out_path, rows_per_class, label_counts, source_files, scanned_files)

    print("wrote: %s" % out_path)
    print("summary: %s" % summary_path)
    print(json.dumps({"total_rows": summary["total_rows"], "missing_labels": summary["missing_labels"]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
