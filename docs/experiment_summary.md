# Experiment Summary

This document records the final expanded CICIDS2017 dynamic-defense experiment and the CENI file-interface validation result.

## Setup

- Dataset scenario: expanded CICIDS2017 ordered scenario, covering 13 labels.
- Detector mode: `hybrid`
- Optimizer: `actor_critic`
- Controller path: REST translating controller
- Controller execution mode: `stateful`
- CENI export: `/tmp/optimize_multi_vm_runtime/defense_inputs/dynamic_defense.json`
- Validation: `optimize/multi_vm/validate_defense_inputs.py`
- Final archive path: `artifacts/final_expanded_rest_stateful_ceni_validation/`

The final archive stores experiment outputs as artifacts. Normal `reports/` and `runtime/` files are generated outputs and should not be committed unless explicitly copied into an `artifacts/` experiment directory.

## Final Metrics

| Metric | Value |
|---|---:|
| `windows` | 11 |
| `adjustment_events` | 11 |
| `detector` | `hybrid` |
| `optimizer` | `actor_critic` |
| `detection_success_rate` | 1.0 |
| `defense_success_rate` | 1.0 |
| CENI validation | `PASS` |

The CENI validation confirms that the generated `dynamic_defense.json` matches the expected input schema for the multi-VM controller integration.

## Commands

Build the expanded ordered scenario from local CICIDS2017 CSV files:

```bash
python scripts/make_cicids2017_subset.py \
  --raw-dir /path/to/CICIDS2017/csv \
  --rows-per-class 200
```

Train the expanded FlowMLP model:

```bash
python scripts/train_torch_flow_classifier.py \
  --input data/cicids2017_subset/cicids2017_expanded_scenario_ordered.csv \
  --model-out models/torch_flow_classifier_expanded.pt \
  --meta-out models/torch_flow_classifier_expanded_meta.json
```

Start the stateful REST controller:

```bash
python scripts/translating_defense_controller.py \
  --host 127.0.0.1 \
  --port 18082 \
  --execution-mode stateful
```

Run dynamic defense against the expanded scenario:

```bash
python attack_defender.py \
  --input data/cicids2017_subset/cicids2017_expanded_scenario_ordered.csv \
  --build-templates \
  --window-size 200 \
  --limit 2200 \
  --detector hybrid \
  --torch-model models/torch_flow_classifier_expanded.pt \
  --torch-meta models/torch_flow_classifier_expanded_meta.json \
  --torch-threshold 0.70 \
  --optimizer actor_critic \
  --adapter rest \
  --controller-endpoint http://127.0.0.1:18082
```

Export CENI controller input:

```bash
python scripts/export_ceni_dynamic_defense_status.py \
  --network-status /tmp/optimize_multi_vm_runtime/defense_feeds/network_status.json \
  --out-json /tmp/optimize_multi_vm_runtime/defense_inputs/dynamic_defense.json
```

Validate on the optimize/multi_vm side:

```bash
python optimize/multi_vm/validate_defense_inputs.py
```

## Execution Boundary

The final experiment uses `ActionExecutor` in `stateful` mode. It updates:

- `runtime/controller_state.json`
- `reports/controller_execution_plan.jsonl`

It does not execute real network-modifying commands. In particular, current experiments do not run real `tc`, `iptables`, or `ovs-ofctl` changes. The network actions `rate_limit` and `isolate_flow` are represented as controller execution plans and SDN/CENI intents for validation.

This boundary is intentional: it keeps the CENI integration safe while proving that the detection, optimization, action translation, state update, execution-plan generation, and CENI JSON export path is complete.

## Model Note

The expanded FlowMLP detector accuracy is approximately `0.757`. This is sufficient for prototype validation and integration testing, but it is not a production-grade traffic classifier. Future work can improve this with:

- broader feature normalization and feature selection;
- per-day CICIDS2017 split control;
- class rebalancing beyond fixed rows per class;
- deeper or better-regularized PyTorch models;
- threshold calibration for hybrid mode;
- evaluation on held-out CICIDS2017 files rather than only the ordered scenario.

## Data Policy

Do not commit raw CICIDS2017 CSV files. Keep raw datasets outside the repository and generate compact scenario CSVs as needed. Generated `reports/` and `runtime/` files should also remain uncommitted unless they are intentionally copied into an `artifacts/` directory as an experiment archive.
