#!/usr/bin/env python3
"""Measure detection generalization against a held-out set NOT authored to match
backend/app/agents/detection_agent.py's keyword lists (unlike labeled_incidents.json,
whose fixtures all share the same 'KEY VALUE' convention as the detector's own
_BENIGN_MARKERS/signature keywords - see backend/data/holdout_generalization_cases.json
for the full rationale).

Runs the real pipeline (ingest_agent -> detection_agent, LLM + rules, not the
rules-only path) against backend/data/holdout_generalization_cases.json and reports
precision/recall/F1 on "did this get correctly flagged as a real threat" - the number
that actually answers whether detection generalizes to unfamiliar log formats/wording.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.agents.detection_agent import detection_agent
from app.agents.ingest_agent import ingest_agent

CASES_PATH = ROOT / "data" / "holdout_generalization_cases.json"
RESULTS_PATH = ROOT / "tests" / "results" / "holdout_generalization_report.json"


async def run_case(raw_logs: List[str]) -> tuple[list, list]:
    state: Dict[str, Any] = {
        "raw_logs": raw_logs,
        "logs": [],
        "alerts": [],
        "agent_execution_log": [],
    }
    state = await ingest_agent(state)
    state = await detection_agent(state)
    alerts = state.get("alerts") or []
    techniques = sorted({t.split(".")[0] for a in alerts for t in (a.mitre_techniques or [])})
    return alerts, techniques


async def main() -> None:
    with open(CASES_PATH) as f:
        data = json.load(f)
    cases = data["cases"]

    per_case = []
    tp = fp = fn = tn = 0

    for case in cases:
        alerts, techniques = await run_case(case["raw_logs"])
        predicted_positive = len(alerts) > 0
        expected_positive = case["expected_is_true_positive"]

        if expected_positive and predicted_positive:
            tp += 1
            outcome = "TP"
        elif not expected_positive and predicted_positive:
            fp += 1
            outcome = "FP"
        elif expected_positive and not predicted_positive:
            fn += 1
            outcome = "FN"
        else:
            tn += 1
            outcome = "TN"

        per_case.append({
            "id": case["id"],
            "name": case["name"],
            "category": case["category"],
            "expected_is_true_positive": expected_positive,
            "predicted_positive": predicted_positive,
            "outcome": outcome,
            "alert_count": len(alerts),
            "alert_titles": [a.title for a in alerts],
            "expected_techniques": case.get("expected_techniques", []),
            "detected_techniques": techniques,
        })

        print(
            f"[{outcome}] {case['id']:10} {case['name'][:55]:55} "
            f"expected_tp={expected_positive!s:5} predicted={predicted_positive!s:5} alerts={len(alerts)}",
            flush=True,
        )

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(cases) if cases else 0.0

    report = {
        "description": "Held-out generalization eval - real pipeline (ingest + LLM/rule detection) "
        "against log formats/wording not present in labeled_incidents.json.",
        "aggregate": {
            "n": len(cases),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "accuracy": round(accuracy, 3),
            "precision": round(precision, 3),
            "recall": round(recall, 3),
            "f1": round(f1, 3),
        },
        "per_case": per_case,
    }

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print("\n=== HELD-OUT GENERALIZATION METRICS ===", flush=True)
    print(f"n={len(cases)} TP={tp} FP={fp} FN={fn} TN={tn}", flush=True)
    print(f"accuracy={report['aggregate']['accuracy']}", flush=True)
    print(f"precision={report['aggregate']['precision']}", flush=True)
    print(f"recall={report['aggregate']['recall']}", flush=True)
    print(f"f1={report['aggregate']['f1']}", flush=True)
    print(f"wrote {RESULTS_PATH}", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
