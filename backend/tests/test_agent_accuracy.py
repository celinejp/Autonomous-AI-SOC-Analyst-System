"""Detection accuracy tests that run the REAL pipeline, without an LLM.

Earlier versions of this file scored a random simulator, which only proved the scoring maths.
These tests run every labeled case through the actual ingest agent and the deterministic
detection path (ATT&CK rule engine + signature/threshold rules + prompt-injection check +
benign filtering) via `detect_rules_only`, so a regression in a parser or a rule fails here.
The LLM layer is not exercised (it is nondeterministic and needs Ollama); it is measured
separately by scripts/eval_detection_metrics.py --mode llm and eval_holdout_generalization.py.
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from app.agents.detection_agent import detect_rules_only
from app.agents.ingest_agent import ingest_agent
from app.core.metrics import calculate_incident_metrics

DATA = Path(__file__).parent.parent / "data"
FIXTURES = Path(__file__).parent / "fixtures" / "test_logs.json"

# Thresholds for the deterministic layer only.
MIN_RECALL = 0.90
MIN_PRECISION = 0.90
MAX_FALSE_POSITIVE_RATE = 0.10


def _analyze(raw_logs: List[str]):
    state: Dict[str, Any] = {"raw_logs": raw_logs, "logs": [], "alerts": [], "agent_execution_log": []}
    state = asyncio.run(ingest_agent(state))
    return detect_rules_only(state["logs"])


def _cases() -> List[Dict[str, Any]]:
    cases = []
    for inc in json.load(open(DATA / "labeled_incidents.json"))["incidents"]:
        cases.append({"id": inc["id"], "attack": bool(inc["is_true_positive"]), "logs": inc["raw_logs"]})
    for sc in json.load(open(FIXTURES))["scenarios"]:
        techs = sc.get("expected_techniques") or []
        cases.append({"id": f"fixture-{sc['name']}", "attack": bool(techs) and sc.get("expected_severity") != "low",
                      "logs": sc["logs"]})
    return cases


@pytest.fixture(scope="module")
def results():
    out = []
    for c in _cases():
        alerts = _analyze(c["logs"])
        out.append({**c, "flagged": bool(alerts), "alerts": alerts})
    return out


class TestRealDetectionAccuracy:
    def test_case_counts(self, results):
        assert len(results) == 25
        assert sum(r["attack"] for r in results) == 17

    def test_recall(self, results):
        attacks = [r for r in results if r["attack"]]
        missed = [r["id"] for r in attacks if not r["flagged"]]
        recall = 1 - len(missed) / len(attacks)
        assert recall >= MIN_RECALL, f"recall {recall:.2f}; missed {missed}"

    def test_precision_and_false_positive_rate(self, results):
        benign = [r for r in results if not r["attack"]]
        false_pos = [r["id"] for r in benign if r["flagged"]]
        flagged = [r for r in results if r["flagged"]]
        precision = sum(r["attack"] for r in flagged) / len(flagged)
        assert precision >= MIN_PRECISION, f"precision {precision:.2f}; false positives {false_pos}"
        assert len(false_pos) / len(benign) <= MAX_FALSE_POSITIVE_RATE, f"false positives: {false_pos}"

    def test_alerts_point_at_real_log_lines(self, results):
        for r in results:
            for alert in r["alerts"]:
                for idx in alert.related_logs:
                    assert 0 <= int(idx) < len(r["logs"]), f"{r['id']}: {alert.title} cites line {idx}"

    def test_holdout_benign_cases_stay_quiet(self):
        """The two ambiguous-benign held-out cases must produce no deterministic alert."""
        cases = json.load(open(DATA / "holdout_generalization_cases.json"))["cases"]
        for c in cases:
            if not c["expected_is_true_positive"]:
                assert _analyze(c["raw_logs"]) == [], c["id"]


class TestMetricsCalculation:
    """Test metrics calculation functions."""
    
    def test_completeness_calculation(self):
        """Test analysis completeness metric."""
        complete_incident = {
            "alerts": [{"title": "test"}],
            "mitre_techniques": [{"id": "T1001"}],
            "incident_report": {
                "executive_summary": "test",
                "technical_findings": "test",
                "root_cause": "test",
                "affected_assets": ["asset"],
                "impact_assessment": "test",
            },
            "response_plan": {
                "containment_actions": [{"action": "test"}],
                "investigation_steps": [{"action": "test"}],
                "remediation_actions": [{"action": "test"}],
            },
            "confidence_score": 0.9,
        }
        
        metrics = calculate_incident_metrics(complete_incident)
        assert metrics.analysis_completeness >= 0.8, \
            f"Expected high completeness, got {metrics.analysis_completeness}"
    
    def test_empty_incident_metrics(self):
        """Test metrics for empty incident."""
        empty_incident = {"incident_id": "empty"}
        
        metrics = calculate_incident_metrics(empty_incident)
        assert metrics.analysis_completeness < 0.5
        assert metrics.response_quality == 0.0
    
    def test_confidence_calculation(self):
        """Test detection confidence calculation."""
        high_confidence_incident = {
            "confidence_score": 0.85,
            "alerts": [{"title": "a"}, {"title": "b"}],
            "mitre_techniques": [{"id": "T1001"}],
            "iteration": 1,
        }
        
        metrics = calculate_incident_metrics(high_confidence_incident)
        assert metrics.detection_confidence >= 0.85


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

