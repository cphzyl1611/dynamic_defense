import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

from src.dynamic_defense.torch_detector import TorchFlowDetector


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--model", default="models/torch_flow_classifier.pt")
    parser.add_argument("--meta", default="models/torch_flow_classifier_meta.json")
    parser.add_argument("--out-csv", default="reports/torch_detector_report.csv")
    parser.add_argument("--out-json", default="reports/torch_detector_summary.json")
    args = parser.parse_args()

    df = pd.read_csv(args.input, nrows=args.limit)
    df.columns = [c.strip() for c in df.columns]

    detector = TorchFlowDetector(model_path=args.model, meta_path=args.meta, device="cpu")
    pred = detector.predict_dataframe(df)

    out = pd.concat([df[["Label"]].reset_index(drop=True), pred], axis=1)
    out["Label"] = out["Label"].astype(str).str.strip()

    accuracy = accuracy_score(out["Label"], out["torch_predicted_label"])
    labels = detector.labels

    summary = {
        "rows": int(len(out)),
        "accuracy": float(accuracy),
        "labels": labels,
        "predicted_counts": out["torch_predicted_label"].value_counts().to_dict(),
        "true_counts": out["Label"].value_counts().to_dict(),
        "model": args.model,
        "meta": args.meta,
        "output_csv": args.out_csv,
    }

    Path(args.out_csv).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.out_csv, index=False)
    Path(args.out_json).write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("\n=== classification report ===")
    print(classification_report(out["Label"], out["torch_predicted_label"], labels=labels))
    print("\n=== confusion matrix ===")
    print(pd.DataFrame(
        confusion_matrix(out["Label"], out["torch_predicted_label"], labels=labels),
        index=[f"true_{x}" for x in labels],
        columns=[f"pred_{x}" for x in labels],
    ))


if __name__ == "__main__":
    main()
