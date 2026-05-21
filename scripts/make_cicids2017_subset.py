from pathlib import Path
import argparse
import pandas as pd


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


def read_clean_csv(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    df = df.replace([float("inf"), float("-inf")], pd.NA)
    existing = [c for c in KEEP_COLUMNS if c in df.columns]
    df = df[existing].dropna()
    return df


def sample_label(df: pd.DataFrame, label: str, n: int) -> pd.DataFrame:
    part = df[df["Label"].astype(str).str.strip() == label]
    if len(part) == 0:
        print(f"[WARN] label not found: {label}")
        return part
    return part.sample(n=min(n, len(part)), random_state=42)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-dir", required=True)
    parser.add_argument("--out", default="data/cicids2017_subset/cicids2017_3attack_subset.csv")
    parser.add_argument("--per-attack", type=int, default=1000)
    parser.add_argument("--benign", type=int, default=1000)
    args = parser.parse_args()

    raw = Path(args.raw_dir)

    ddos = read_clean_csv(raw / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    portscan = read_clean_csv(raw / "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv")
    tuesday = read_clean_csv(raw / "Tuesday-WorkingHours.pcap_ISCX.csv")

    parts = [
        sample_label(ddos, "DDoS", args.per_attack),
        sample_label(portscan, "PortScan", args.per_attack),
        sample_label(tuesday, "SSH-Patator", args.per_attack),
        sample_label(tuesday, "FTP-Patator", args.per_attack),
        sample_label(ddos, "BENIGN", args.benign // 3),
        sample_label(portscan, "BENIGN", args.benign // 3),
        sample_label(tuesday, "BENIGN", args.benign // 3),
    ]

    out = pd.concat(parts, ignore_index=True)
    out = out.sample(frac=1.0, random_state=42).reset_index(drop=True)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_path, index=False)

    print(f"wrote: {out_path}")
    print(out["Label"].value_counts())


if __name__ == "__main__":
    main()
