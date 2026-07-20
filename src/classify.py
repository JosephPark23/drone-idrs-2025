#!/usr/bin/env python3
import time
from typing import Any, Dict, List

from rules_analyze import Rules


class Classification:
    # Rules-based detection component to detect
    # 1) Deauth attacks (basically any deauth frames)
    # 2) Unauthorized connection attempts (auth/assoc/EAPOL type frames from unrecognized MACs)
    # Most of the logic is actually in other files but this script helps facilitate the flow of data

    def __init__(self, rules: Rules):
        self.rules = rules

    # run the window statistics through the rules
    def analyze_window(self, packets: List[Dict[str, Any]]) -> Dict[str, Any]:
        t0 = time.perf_counter()

        rules_result = self.rules.analyze_window(packets)
        rules_ok = rules_result["ok"]
        n_violations = rules_result["n_violations"]
        is_attack = not rules_ok
        latency_total = (time.perf_counter() - t0) * 1000

        return {
            "final_label": "ATTACK" if is_attack else "BENIGN",
            "rules_ok": rules_ok,
            "rules_violations": rules_result["reasons"],
            "n_packets": len(packets),
            "latency_total_ms": latency_total,
        }


def create_classification(config: Dict[str, Any]) -> Classification:
    # create a classification instance
    from rules_analyze import create_rules_from_config

    rules = create_rules_from_config(config)
    return Classification(rules=rules)
