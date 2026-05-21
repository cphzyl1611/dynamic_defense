from pathlib import Path
import argparse
import json

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report


FEATURE_COLUMNS = [
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
]


class FlowMLP(nn.Module):
    def __init__(self, input_dim: int, num_classes: int):
        super().__init__()
        self.net = nn.Sequential(
            nn.Linear(input_dim, 64),
            nn.ReLU(),
            nn.Dropout(0.15),
            nn.Linear(64, 32),
            nn.ReLU(),
            nn.Linear(32, num_classes),
        )

    def forward(self, x):
        return self.net(x)


def load_dataset(path: str):
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]

    missing = [c for c in FEATURE_COLUMNS + ["Label"] if c not in df.columns]
    if missing:
        raise RuntimeError(f"Missing columns: {missing}")

    df = df.replace([np.inf, -np.inf], np.nan).dropna(subset=FEATURE_COLUMNS + ["Label"])
    df["Label"] = df["Label"].astype(str).str.strip()

    x = df[FEATURE_COLUMNS].astype("float32").values
    y = df["Label"].values
    return x, y


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="data/cicids2017_subset/cicids2017_3attack_subset.csv")
    parser.add_argument("--model-out", default="models/torch_flow_classifier.pt")
    parser.add_argument("--meta-out", default="models/torch_flow_classifier_meta.json")
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--lr", type=float, default=1e-3)
    args = parser.parse_args()

    # 强制 CPU，避免误调用 GPU。
    device = torch.device("cpu")

    x, y_raw = load_dataset(args.input)

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(y_raw)

    scaler = StandardScaler()
    x = scaler.fit_transform(x).astype("float32")

    x_train, x_test, y_train, y_test = train_test_split(
        x,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    train_x = torch.tensor(x_train, dtype=torch.float32)
    train_y = torch.tensor(y_train, dtype=torch.long)
    test_x = torch.tensor(x_test, dtype=torch.float32)
    test_y = torch.tensor(y_test, dtype=torch.long)

    model = FlowMLP(input_dim=train_x.shape[1], num_classes=len(label_encoder.classes_)).to(device)
    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    num_samples = train_x.shape[0]

    for epoch in range(1, args.epochs + 1):
        model.train()
        indices = torch.randperm(num_samples)
        total_loss = 0.0

        for start in range(0, num_samples, args.batch_size):
            batch_idx = indices[start:start + args.batch_size]
            bx = train_x[batch_idx].to(device)
            by = train_y[batch_idx].to(device)

            optimizer.zero_grad()
            logits = model(bx)
            loss = criterion(logits, by)
            loss.backward()
            optimizer.step()

            total_loss += loss.item() * len(batch_idx)

        if epoch == 1 or epoch % 5 == 0 or epoch == args.epochs:
            model.eval()
            with torch.no_grad():
                logits = model(test_x.to(device))
                pred = logits.argmax(dim=1).cpu().numpy()
                acc = accuracy_score(y_test, pred)
            print(f"epoch={epoch:03d} loss={total_loss / num_samples:.4f} test_acc={acc:.4f}")

    model.eval()
    with torch.no_grad():
        logits = model(test_x.to(device))
        pred = logits.argmax(dim=1).cpu().numpy()

    acc = accuracy_score(y_test, pred)
    print("\nFinal accuracy:", acc)
    print(classification_report(y_test, pred, target_names=label_encoder.classes_))

    model_path = Path(args.model_out)
    meta_path = Path(args.meta_out)
    model_path.parent.mkdir(parents=True, exist_ok=True)

    torch.save(model.state_dict(), model_path)

    meta = {
        "model_type": "FlowMLP",
        "feature_columns": FEATURE_COLUMNS,
        "labels": label_encoder.classes_.tolist(),
        "scaler_mean": scaler.mean_.tolist(),
        "scaler_scale": scaler.scale_.tolist(),
        "input_dim": len(FEATURE_COLUMNS),
        "num_classes": len(label_encoder.classes_),
        "device": "cpu",
        "accuracy": float(acc),
    }
    meta_path.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"\nSaved model: {model_path}")
    print(f"Saved meta: {meta_path}")


if __name__ == "__main__":
    main()
