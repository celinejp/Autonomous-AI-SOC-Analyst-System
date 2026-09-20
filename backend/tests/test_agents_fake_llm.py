"""LLM-dependent code paths (retries, fallbacks, timeouts, the reflection loop) tested with a
fake model that returns canned text, so they need no Ollama and are deterministic."""

import asyncio
import importlib
import json
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.core.config import settings
from app.models.incident import Alert, IncidentReport, Severity
from app.orchestrator.langgraph_workflow import run_workflow_with_events, should_continue_reflection

SSH = [f"Jan 15 10:30:0{i} host sshd[1]: Failed password for root from 203.0.113.9 port 22" for i in range(6)]

ALERT_JSON = json.dumps([{
    "severity": "high", "title": "LLM brute force", "description": "many failures",
    "detection_rule": "LLM-detected pattern", "evidence": ["6 failed logins"],
    "mitre_techniques": ["T1110"], "related_log_indices": [0, 1, 2],
}])
REPORT_JSON = json.dumps({
    "executive_summary": "Brute force against root.", "technical_findings": "T1110 observed.",
    "timeline": [], "affected_assets": ["203.0.113.9"], "root_cause": "Weak password policy",
    "impact_assessment": "Possible account takeover", "confidence_score": 0.9,
    "reasoning_process": ["six failures in seconds"], "detection_gaps": [], "lessons_learned": [],
    "indicators_of_compromise": [],
})
PLAN_JSON = json.dumps({"containment_actions": [{
    "priority": "immediate", "action_type": "block_ip", "action": "Block IP", "description": "Block source",
    "target": "203.0.113.9", "assigned_team": "Network", "status": "pending"}]})


def critic_json(conf, revise):
    return json.dumps({"confidence_score": conf, "needs_revision": revise, "feedback": ["fb"],
                       "false_positive_likelihood": 0.1})


class FakeLLM:
    """Replies by agent (recognised from the system prompt); `script` maps agent -> list of replies
    (an Exception instance is raised; the last item repeats)."""

    def __init__(self, script):
        self.script, self.calls, self.delay = script, {}, 0

    def bind_tools(self, _tools):
        return self

    async def ainvoke(self, messages):
        system = (messages[0].content if isinstance(messages, list) else "").lower()
        markers = {"you are a security detection agent": "detection", "you are a threat intelligence agent": "threat intelligence",
                   "you are a tier 2 soc analyst": "tier 2", "you are a critic agent": "critic",
                   "you are a cybersecurity response planner": "response planner"}
        agent = next((name for phrase, name in markers.items() if phrase in system), "other")
        n = self.calls[agent] = self.calls.get(agent, 0) + 1
        if self.delay:
            await asyncio.sleep(self.delay)
        replies = self.script.get(agent, [""])
        reply = replies[min(n - 1, len(replies) - 1)]
        if isinstance(reply, Exception):
            raise reply
        return SimpleNamespace(content=reply, tool_calls=[])


def patch_llm(monkeypatch, fake):
    # (app.agents re-exports functions named like their modules, so resolve modules explicitly)
    for mod in ("detection_agent", "threat_intel_agent", "analyst_agent", "critic_agent", "response_planner"):
        monkeypatch.setattr(importlib.import_module(f"app.agents.{mod}"), "get_llm", lambda *a, **k: fake)
    intel = importlib.import_module("app.agents.threat_intel_agent")
    monkeypatch.setattr(intel, "search_mitre_techniques_raw", lambda *a, **k: [])
    monkeypatch.setattr(intel, "get_mitre_technique_raw",
                        lambda tid: {"id": tid, "name": "x", "tactic": "y", "description": "z", "detection_methods": []})


def make_state(logs=None, **extra):
    from app.agents.ingest_agent import ingest_agent
    state = {"raw_logs": logs or SSH, "logs": [], "alerts": [], "threat_intel": {}, "incident_report": None,
             "response_plan": None, "confidence": 0.0, "iteration": 0, "needs_revision": False,
             "critique_feedback": None, "messages": [], "agent_execution_log": [], "incident_id": "t"}
    state.update(extra)
    return asyncio.run(ingest_agent(state))


def sample_report(conf=0.6):
    return IncidentReport(executive_summary="s", technical_findings="t", root_cause="r", impact_assessment="i",
                          confidence_score=conf)


def sample_alert():
    return Alert(timestamp=datetime.utcnow(), severity=Severity.HIGH, title="a", description="d",
                 detection_rule="ATT&CK Rule: T1110.001", related_logs=["0"], mitre_techniques=["T1110.001"])


class TestDetectionDegradation:
    def run(self, monkeypatch, replies):
        from app.agents.detection_agent import detection_agent
        fake = FakeLLM({"detection": replies})
        patch_llm(monkeypatch, fake)
        return asyncio.run(detection_agent(make_state())), fake

    def test_valid_llm_alerts_are_kept(self, monkeypatch):
        state, _ = self.run(monkeypatch, [ALERT_JSON])
        assert any(a.title == "LLM brute force" for a in state["alerts"])

    def test_one_bad_response_is_retried(self, monkeypatch):
        state, fake = self.run(monkeypatch, ["not json at all", ALERT_JSON])
        assert fake.calls["detection"] == 2
        assert any(a.title == "LLM brute force" for a in state["alerts"])

    def test_two_bad_responses_fall_back_to_rules(self, monkeypatch):
        state, fake = self.run(monkeypatch, ["nope", "still nope"])
        assert fake.calls["detection"] == 2
        assert state["alerts"] and all(a.title != "LLM brute force" for a in state["alerts"])

    def test_llm_outage_still_produces_rule_alerts(self, monkeypatch):
        state, _ = self.run(monkeypatch, [ConnectionError("ollama down")])
        assert state["alerts"], "rules must still fire when the LLM is down"
        assert "ConnectionError" in state["agent_execution_log"][-1]["output_data"]["llm_error"]

    def test_llm_timeout_is_bounded(self, monkeypatch):
        from app.agents.detection_agent import detection_agent
        fake = FakeLLM({"detection": [ALERT_JSON]})
        fake.delay = 5
        patch_llm(monkeypatch, fake)
        monkeypatch.setattr(settings, "llm_timeout_seconds", 0.05)
        state = asyncio.run(detection_agent(make_state()))
        assert state["alerts"] and "TimeoutError" in state["agent_execution_log"][-1]["output_data"]["llm_error"]


class TestAnalystAndPlannerFallbacks:
    def test_analyst_parses_report(self, monkeypatch):
        from app.agents.analyst_agent import analyst_agent
        patch_llm(monkeypatch, FakeLLM({"tier 2": [REPORT_JSON]}))
        state = asyncio.run(analyst_agent(make_state(alerts=[sample_alert()])))
        assert state["incident_report"].root_cause == "Weak password policy"

    def test_analyst_falls_back_after_two_bad_responses(self, monkeypatch):
        from app.agents.analyst_agent import analyst_agent
        fake = FakeLLM({"tier 2": ["garbage", "garbage"]})
        patch_llm(monkeypatch, fake)
        state = asyncio.run(analyst_agent(make_state(alerts=[sample_alert()])))
        assert fake.calls["tier 2"] == 2
        assert state["incident_report"].root_cause == "Analysis in progress"

    def test_analyst_saves_a_report_when_llm_is_down(self, monkeypatch):
        from app.agents.analyst_agent import analyst_agent
        patch_llm(monkeypatch, FakeLLM({"tier 2": [TimeoutError()]}))
        state = asyncio.run(analyst_agent(make_state(alerts=[sample_alert()])))
        assert state["incident_report"] is not None

    def test_planner_groups_actions_by_team(self, monkeypatch):
        from app.agents.response_planner import response_planner_agent
        patch_llm(monkeypatch, FakeLLM({"response planner": [PLAN_JSON]}))
        state = asyncio.run(response_planner_agent(make_state(alerts=[sample_alert()], incident_report=sample_report())))
        assert list(state["response_plan"].actions_by_team) == ["Network"]

    def test_planner_uses_fallback_plan_on_garbage(self, monkeypatch):
        from app.agents.response_planner import response_planner_agent
        patch_llm(monkeypatch, FakeLLM({"response planner": ["oops"]}))
        state = asyncio.run(response_planner_agent(make_state(alerts=[sample_alert()], incident_report=sample_report())))
        assert state["response_plan"].investigation_steps


class TestCriticAndLoop:
    def test_low_confidence_requests_revision(self, monkeypatch):
        from app.agents.critic_agent import critic_agent
        patch_llm(monkeypatch, FakeLLM({"critic": [critic_json(0.4, True)]}))
        state = asyncio.run(critic_agent(make_state(alerts=[sample_alert()], incident_report=sample_report())))
        assert state["needs_revision"] and state["iteration"] == 1

    def test_revision_is_capped_at_three_rounds(self, monkeypatch):
        from app.agents.critic_agent import critic_agent
        patch_llm(monkeypatch, FakeLLM({"critic": [critic_json(0.4, True)]}))
        state = asyncio.run(critic_agent(make_state(alerts=[sample_alert()], incident_report=sample_report(), iteration=3)))
        assert state["needs_revision"] is False

    def test_critic_outage_accepts_report_instead_of_looping(self, monkeypatch):
        from app.agents.critic_agent import critic_agent
        patch_llm(monkeypatch, FakeLLM({"critic": [ConnectionError("down")]}))
        state = asyncio.run(critic_agent(make_state(alerts=[sample_alert()], incident_report=sample_report())))
        assert state["needs_revision"] is False

    @pytest.mark.parametrize("state,expected", [
        ({"needs_revision": True, "iteration": 1, "confidence": 0.4}, "continue"),
        ({"needs_revision": True, "iteration": 3, "confidence": 0.4}, "end"),
        ({"needs_revision": True, "iteration": 1, "confidence": 0.8}, "end"),
        ({"needs_revision": False, "iteration": 0, "confidence": 0.1}, "end"),
    ])
    def test_routing_function(self, state, expected):
        assert should_continue_reflection(state) == expected

    def test_full_graph_reruns_analyst_until_critic_is_satisfied(self, monkeypatch):
        fake = FakeLLM({
            "detection": [ALERT_JSON], "threat intelligence": [""], "tier 2": [REPORT_JSON],
            "critic": [critic_json(0.4, True), critic_json(0.4, True), critic_json(0.9, False)],
            "response planner": [PLAN_JSON],
        })
        patch_llm(monkeypatch, fake)

        async def run():
            final = None
            async for ev in run_workflow_with_events(SSH, "loop-test"):
                if ev["type"] == "complete":
                    final = ev["data"]
                assert ev["type"] != "error", ev
            return final

        final = asyncio.run(run())
        assert fake.calls["tier 2"] == 3 and fake.calls["critic"] == 3
        assert final["response_plan"]["containment_actions"]
