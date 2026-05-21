import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_cmd(args):
    subprocess.check_call([sys.executable] + args, cwd=str(ROOT))


def test_strategy_loader_outputs_metadata():
    run_cmd([
        "strategy_loader.py",
        "--config", "configs/strategies.yaml",
        "--db", "data/policies.sqlite",
    ])

    output = ROOT / "reports" / "strategy_metadata.json"
    assert output.exists()

    data = json.loads(output.read_text(encoding="utf-8"))
    assert data["loaded"] >= 3

    first = data["policies"][0]
    assert "strategy_id" in first
    assert "model_type" in first
    assert "last_updated_at" in first


def test_feature_analyzer_outputs_matches():
    run_cmd([
        "scripts/make_sample_cicids.py",
        "--out", "data/sample_cicids.csv",
    ])

    run_cmd([
        "feature_analyzer.py",
        "--input", "data/sample_cicids.csv",
        "--build-templates",
        "--limit", "300",
    ])

    summary_file = ROOT / "reports" / "feature_match_summary.json"
    report_file = ROOT / "reports" / "feature_match_report.csv"

    assert summary_file.exists()
    assert report_file.exists()

    summary = json.loads(summary_file.read_text(encoding="utf-8"))
    assert summary["rows"] == 300
    assert len(summary["matched_attack_counts"]) >= 1


def test_attack_defender_outputs_adjustment_events():
    run_cmd([
        "scripts/make_sample_cicids.py",
        "--out", "data/sample_cicids.csv",
    ])

    run_cmd([
        "attack_defender.py",
        "--input", "data/sample_cicids.csv",
        "--build-templates",
        "--window-size", "100",
        "--limit", "700",
    ])

    summary_file = ROOT / "reports" / "dynamic_defense_summary.json"
    events_file = ROOT / "reports" / "dynamic_defense_events.csv"

    assert summary_file.exists()
    assert events_file.exists()

    summary = json.loads(summary_file.read_text(encoding="utf-8"))
    assert summary["windows"] >= 1
    assert summary["adjustment_events"] >= 1
    assert summary["defense_success_rate"] >= 0.8
