from __future__ import annotations

from dataclasses import asdict
from typing import Dict, List, Optional

import numpy as np
import pandas as pd

from .ceni_adapter import CeniActionAdapter
from .feature_extractor import ThreatFeatureMatcher, normalize_columns
from .optimizer import ActorCriticLikeOptimizer
from .policy_store import PolicyStore


BENIGN_LABELS = {"BENIGN", "NORMAL", "0"}


class DynamicDefenseEngine:
    def __init__(
        self,
        store: PolicyStore,
        matcher: ThreatFeatureMatcher,
        adapter: CeniActionAdapter,
        epsilon: float = 0.05,
        confidence_threshold: float = 0.25,
    ):
        self.store = store
        self.matcher = matcher
        self.adapter = adapter
        self.optimizer = ActorCriticLikeOptimizer(store, epsilon=epsilon)
        self.confidence_threshold = confidence_threshold
        self.current_strategy_id = None

    @staticmethod
    def _is_attack_label(label: str) -> bool:
        return str(label).strip().upper() not in BENIGN_LABELS and str(label).strip() != ""

    def run_on_csv(self, csv_path: str, window_size: int = 200, limit: Optional[int] = None) -> pd.DataFrame:
        df = pd.read_csv(csv_path, nrows=limit)
        df = normalize_columns(df)
        events = []
        for start in range(0, len(df), window_size):
            window = df.iloc[start : start + window_size]
            if window.empty:
                continue
            events.extend(self._handle_window(window, window_id=start // window_size))
        return pd.DataFrame(events)

    def _handle_window(self, window: pd.DataFrame, window_id: int) -> List[Dict]:
        matches = [self.matcher.match_row(row) for _, row in window.iterrows()]
        attack_votes = pd.Series([m.attack_type for m in matches]).value_counts()
        attack_type = str(attack_votes.index[0]) if not attack_votes.empty else "UNKNOWN"
        avg_score = float(np.mean([m.score for m in matches])) if matches else 0.0
        policy = self.optimizer.select(attack_type)

        labels = window["Label"].astype(str) if "Label" in window.columns else pd.Series([""] * len(window))
        attack_present = any(self._is_attack_label(x) for x in labels)
        detected_as_attack = attack_type != "UNKNOWN" and avg_score >= self.confidence_threshold
        success = (attack_present and detected_as_attack) or ((not attack_present) and (not detected_as_attack))
        # 奖励函数：检出攻击得分高；误报/漏报惩罚；策略代价作为负项。
        if attack_present and detected_as_attack:
            reward = 1.0 + min(avg_score, 1.0) - policy.cost
        elif not attack_present and not detected_as_attack:
            reward = 0.6 - policy.cost
        else:
            reward = -1.0 - policy.cost
        self.optimizer.observe(policy.strategy_id, reward=reward, success=success)

        adjustment_triggered = self.current_strategy_id != policy.strategy_id or attack_present
        self.current_strategy_id = policy.strategy_id
        context = {
            "window_id": window_id,
            "attack_type": attack_type,
            "avg_match_score": avg_score,
            "attack_present_by_label": attack_present,
            "rows": int(len(window)),
        }
        action_results = self.adapter.execute_actions(policy.strategy_id, policy.actions, context) if adjustment_triggered else []
        return [
            {
                "window_id": window_id,
                "rows": int(len(window)),
                "attack_type": attack_type,
                "avg_match_score": avg_score,
                "strategy_id": policy.strategy_id,
                "model_type": policy.model_type,
                "adjustment_triggered": bool(adjustment_triggered),
                "defense_success": bool(success),
                "reward": float(reward),
                "actions": [asdict(r) for r in action_results],
            }
        ]
