"""Parsing and normalisation of LLM output in the Critic, Planner and Analyst (no LLM needed)."""

import json
from datetime import datetime

import pytest

from app.agents.analyst_agent import _merge_llm_iocs, _parse_detection_gaps, _severity_to_ioc_action
from app.agents.critic_agent import _feedback_text, _parse_critique
from app.agents.response_planner import _fallback_plan, _normalize_action, _parse_response_plan
from app.models.incident import Alert, IncidentReport, Severity


def report(conf=0.6):
    return IncidentReport(executive_summary="s", technical_findings="t", root_cause="r", impact_assessment="i", confidence_score=conf)


class TestCritic:
    def test_json_critique_is_parsed(self):
        out = _parse_critique(json.dumps({"confidence_score": 0.4, "needs_revision": True, "feedback": ["a", "b"],
                                          "false_positive_likelihood": 0.7}), report())
        assert out["confidence"] == 0.4 and out["needs_revision"] and out["false_positive_likelihood"] == 0.7
        assert out["feedback"] == "- a\n- b", "list feedback is flattened to text"

    def test_missing_fields_fall_back_to_the_reports_confidence(self):
        out = _parse_critique("{}", report(0.66))
        assert out["confidence"] == 0.66 and out["needs_revision"] is False

    @pytest.mark.parametrize("text,revise", [
        ("Low confidence: the evidence is uncertain", True),
        ("This looks like a false positive", True),
        ("The findings are inconsistent", True),
        ("Solid analysis, high confidence", False),
    ])
    def test_prose_critique_uses_keyword_fallback(self, text, revise):
        assert _parse_critique(text, report())["needs_revision"] is revise

    def test_feedback_text(self):
        assert _feedback_text(["x"]) == "- x" and _feedback_text("plain") == "plain"


class TestResponsePlanner:
    def test_alternate_key_names_are_accepted(self):
        action = _normalize_action({"title": "Block IP", "team": "Network", "asset": "1.2.3.4", "type": "block_ip"})
        assert (action.action, action.assigned_team, action.target, action.action_type) == ("Block IP", "Network", "1.2.3.4", "block_ip")

    def test_defaults_fill_missing_fields(self):
        action = _normalize_action({"description": "do it"}, {"priority": "immediate", "assigned_team": "IAM"})
        assert action.priority == "immediate" and action.assigned_team == "IAM" and action.status == "pending"

    def test_non_dict_items_are_ignored(self):
        assert _normalize_action("just text") is None

    def test_valid_plan_is_parsed(self):
        plan = _parse_response_plan(json.dumps({"containment_actions": [{"action": "Block", "assigned_team": "Network"}]}), [], report())
        assert plan.containment_actions[0].assigned_team == "Network"

    @pytest.mark.parametrize("content", ["not json", "{}", '{"containment_actions": []}'])
    def test_unusable_output_gives_the_fixed_fallback_plan(self, content):
        alert = Alert(timestamp=datetime.utcnow(), severity=Severity.HIGH, title="a", description="d", detection_rule="r")
        plan = _parse_response_plan(content, [alert], report())
        assert plan.investigation_steps and plan.containment_actions

    def test_fallback_plan_only_contains_containment_for_high_severity(self):
        low = Alert(timestamp=datetime.utcnow(), severity=Severity.MEDIUM, title="a", description="d", detection_rule="r")
        assert _fallback_plan([low]).containment_actions == []


class TestAnalystHelpers:
    @pytest.mark.parametrize("severity,action", [(Severity.CRITICAL, "block"), (Severity.HIGH, "block"),
                                                 (Severity.MEDIUM, "investigate"), (Severity.LOW, "monitor")])
    def test_ioc_action_follows_alert_severity(self, severity, action):
        assert _severity_to_ioc_action(severity) == action

    def test_llm_iocs_are_filtered_and_normalised(self):
        buckets = {b: [] for b in ("ip_addresses", "domains", "urls", "file_hashes", "email_addresses")}
        _merge_llm_iocs(buckets, [
            {"value": "evil.example", "type": "domain", "confidence": "banana", "recommended_action": "explode"},
            {"value": "invented.example", "type": "domain"},      # not in the logs
            {"value": "x", "type": "unknown-type"},               # bad type
            "not a dict",
        ], observed="contacted evil.example over dns")
        assert [(e.value, e.confidence, e.recommended_action) for e in buckets["domains"]] == [("evil.example", "medium", "investigate")]

    def test_detection_gaps_accept_strings_and_dicts(self):
        gaps = _parse_detection_gaps(["no sysmon", {"description": "no dns logs", "priority": "high"}, {"nodesc": 1}])
        assert [g.description for g in gaps] == ["no sysmon", "no dns logs"]
        assert _parse_detection_gaps("garbage") == []
