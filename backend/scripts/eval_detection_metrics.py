#!/usr/bin/env python3
"""Measure real detection precision/recall/F1 against labeled fixtures.

Runs the actual ingest + detection code paths (not the random simulator).
Modes:
  - rules: ingest + ATT&CK rules + rule-based fallback (no LLM)
  - llm:   ingest + full detection_agent (includes LLM + rules)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.agents.detection_agent import detection_agent, _rule_based_detection
from app.agents.ingest_agent import ingest_agent
from app.agents.threat_intel_agent import threat_intel_agent
from app.detection.attack_rules import evaluate_attack_rules
from app.models.incident import Alert, Severity


LABELED_PATH = ROOT / "data" / "labeled_incidents.json"
FIXTURES_PATH = ROOT / "tests" / "fixtures" / "test_logs.json"
RESULTS_PATH = ROOT / "tests" / "results" / "real_accuracy_report.json"


def load_cases() -> List[Dict[str, Any]]:
    cases: List[Dict[str, Any]] = []

    with open(LABELED_PATH) as f:
        labeled = json.load(f)
    for inc in labeled.get("incidents", []):
        cases.append(
            {
                "id": inc["id"],
                "name": inc["name"],
                "source": "labeled_incidents",
                "is_true_positive": bool(inc.get("is_true_positive", True)),
                "expected_techniques": list(inc.get("mitre_techniques") or []),
                "expected_severity": inc.get("severity"),
                "raw_logs": list(inc.get("raw_logs") or []),
            }
        )

    with open(FIXTURES_PATH) as f:
        fixtures = json.load(f)
    for sc in fixtures.get("scenarios", []):
        expected_techs = list(sc.get("expected_techniques") or [])
        is_tp = len(expected_techs) > 0 and sc.get("expected_severity") != "low"
        cases.append(
            {
                "id": f"fixture-{sc['name']}",
                "name": sc["name"],
                "source": "test_logs_fixtures",
                "is_true_positive": is_tp,
                "expected_techniques": expected_techs,
                "expected_severity": sc.get("expected_severity"),
                "raw_logs": list(sc.get("logs") or []),
            }
        )

    return cases


def _technique_ids(alerts: List[Any]) -> Set[str]:
    ids: Set[str] = set()
    for alert in alerts:
        techs = getattr(alert, "mitre_techniques", None)
        if techs is None and isinstance(alert, dict):
            techs = alert.get("mitre_techniques") or ([alert.get("technique_id")] if alert.get("technique_id") else [])
        for t in techs or []:
            if isinstance(t, dict):
                tid = t.get("technique_id") or t.get("id")
            else:
                tid = str(t)
            if tid:
                ids.add(tid.split(".")[0])  # normalize T1110.001 -> T1110
    return ids


async def run_rules_only(raw_logs: List[str], enrich: bool = False) -> Tuple[List[Alert], Set[str]]:
    state: Dict[str, Any] = {
        "raw_logs": raw_logs,
        "logs": [],
        "alerts": [],
        "agent_execution_log": [],
    }
    state = await ingest_agent(state)
    logs = state.get("logs") or []

    alerts: List[Alert] = list(_rule_based_detection(logs))
    for attack_alert in evaluate_attack_rules(logs):
        alerts.append(
            Alert(
                timestamp=datetime.now(timezone.utc).replace(tzinfo=None),
                severity=Severity(attack_alert["severity"]),
                title=f"{attack_alert['name']} - {attack_alert['technique_id']}",
                description=f"Detected {attack_alert['tactic']} technique: {attack_alert['name']}",
                detection_rule=f"ATT&CK Rule: {attack_alert['technique_id']}",
                related_logs=attack_alert.get("matched_logs", []),
                mitre_techniques=[attack_alert["technique_id"]],
                evidence=[{"rule": attack_alert["technique_id"], "confidence": attack_alert.get("confidence", 0.75)}],
            )
        )
    if enrich and alerts:
        state["alerts"] = alerts
        state = await threat_intel_agent(state)
        alerts = state.get("alerts") or alerts
    return alerts, _technique_ids(alerts)


async def run_llm_detection(raw_logs: List[str], enrich: bool = False) -> Tuple[List[Alert], Set[str]]:
    state: Dict[str, Any] = {
        "raw_logs": raw_logs,
        "logs": [],
        "alerts": [],
        "agent_execution_log": [],
    }
    state = await ingest_agent(state)
    state = await detection_agent(state)
    alerts = state.get("alerts") or []
    if enrich and alerts:
        state["alerts"] = alerts
        state = await threat_intel_agent(state)
        alerts = state.get("alerts") or alerts
    return alerts, _technique_ids(alerts)


def binary_metrics(y_true: List[bool], y_pred: List[bool]) -> Dict[str, float]:
    tp = sum(1 for t, p in zip(y_true, y_pred) if t and p)
    fp = sum(1 for t, p in zip(y_true, y_pred) if (not t) and p)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t and (not p))
    tn = sum(1 for t, p in zip(y_true, y_pred) if (not t) and (not p))
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / max(len(y_true), 1)
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    detection_rate = recall  # same as recall for binary alert/no-alert
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "accuracy": round(accuracy, 3),
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "false_positive_rate": round(fpr, 3),
        "detection_rate": round(detection_rate, 3),
        "n": len(y_true),
    }


async def evaluate(mode: str, sources: Optional[Set[str]] = None, enrich: bool = False) -> Dict[str, Any]:
    cases = load_cases()
    if sources:
        cases = [c for c in cases if c["source"] in sources]

    per_case = []
    y_true: List[bool] = []
    y_pred: List[bool] = []
    technique_hits = 0
    technique_total = 0  # sum(|expected|) -- recall denominator
    technique_predicted_total = 0  # sum(|detected|) -- precision denominator

    for case in cases:
        if not case["raw_logs"]:
            continue
        try:
            if mode == "llm":
                alerts, detected = await run_llm_detection(case["raw_logs"], enrich=enrich)
            else:
                alerts, detected = await run_rules_only(case["raw_logs"], enrich=enrich)
            predicted = len(alerts) > 0
            err = None
        except Exception as e:
            alerts, detected, predicted = [], set(), False
            err = str(e)

        expected = {t.split(".")[0] for t in case["expected_techniques"]}
        if expected:
            technique_total += len(expected)
            technique_hits += len(expected & detected)
        if detected:
            technique_predicted_total += len(detected)

        y_true.append(case["is_true_positive"])
        y_pred.append(predicted)
        per_case.append(
            {
                "id": case["id"],
                "name": case["name"],
                "source": case["source"],
                "is_true_positive": case["is_true_positive"],
                "predicted_positive": predicted,
                "alert_count": len(alerts),
                "expected_techniques": sorted(expected),
                "detected_techniques": sorted(detected),
                "correct": predicted == case["is_true_positive"],
                "error": err,
            }
        )
        status = "OK" if predicted == case["is_true_positive"] else "MISS"
        print(
            f"[{status}] {case['id']:24} tp={case['is_true_positive']!s:5} "
            f"pred={predicted!s:5} alerts={len(alerts):2} err={err}",
            flush=True,
        )

    metrics = binary_metrics(y_true, y_pred)
    tech_recall = round(technique_hits / technique_total, 3) if technique_total else None
    tech_precision = (
        round(technique_hits / technique_predicted_total, 3) if technique_predicted_total else None
    )
    tech_f1 = (
        round(2 * tech_precision * tech_recall / (tech_precision + tech_recall), 3)
        if tech_precision and tech_recall
        else None
    )
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": mode,
        "enrich": enrich,
        "description": (
            "Real detection metrics from ingest + ATT&CK/rule engines"
            if mode == "rules"
            else "Real detection metrics from ingest + detection_agent (LLM + rules)"
        ) + (" + threat_intel_agent enrichment" if enrich else ""),
        "aggregate": {
            **metrics,
            "mitre_technique_recall": tech_recall,
            "mitre_technique_precision": tech_precision,
            "mitre_technique_f1": tech_f1,
            "mitre_technique_hits": technique_hits,
            "mitre_technique_expected_total": technique_total,
            "mitre_technique_predicted_total": technique_predicted_total,
        },
        "per_case": per_case,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["rules", "llm"], default="rules")
    parser.add_argument(
        "--source",
        action="append",
        choices=["labeled_incidents", "test_logs_fixtures"],
        help="Filter dataset source (repeatable). Default: both.",
    )
    parser.add_argument(
        "--enrich",
        action="store_true",
        help="Also run threat_intel_agent (Qdrant MITRE enrichment) after detection, "
        "so mitre_technique_precision reflects real over-tagging behavior.",
    )
    args = parser.parse_args()
    sources = set(args.source) if args.source else None

    print(f"Evaluating mode={args.mode} sources={sources or 'all'} enrich={args.enrich}...", flush=True)
    report = asyncio.run(evaluate(args.mode, sources, enrich=args.enrich))

    RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    suffix = ("_llm" if args.mode == "llm" else "") + ("_enrich" if args.enrich else "")
    out = RESULTS_PATH if not suffix else RESULTS_PATH.with_name(f"real_accuracy_report{suffix}.json")
    with open(out, "w") as f:
        json.dump(report, f, indent=2)

    agg = report["aggregate"]
    print("\n=== REAL DETECTION METRICS ===", flush=True)
    print(f"mode={args.mode} n={agg['n']}", flush=True)
    print(f"TP={agg['tp']} FP={agg['fp']} FN={agg['fn']} TN={agg['tn']}", flush=True)
    print(f"accuracy={agg['accuracy']}", flush=True)
    print(f"precision={agg['precision']}", flush=True)
    print(f"recall={agg['recall']} (detection_rate)", flush=True)
    print(f"f1={agg['f1']}", flush=True)
    print(f"false_positive_rate={agg['false_positive_rate']}", flush=True)
    print(f"mitre_technique_recall={agg['mitre_technique_recall']}", flush=True)
    print(f"mitre_technique_precision={agg['mitre_technique_precision']}", flush=True)
    print(f"mitre_technique_f1={agg['mitre_technique_f1']}", flush=True)
    print(f"wrote {out}", flush=True)


if __name__ == "__main__":
    main()
