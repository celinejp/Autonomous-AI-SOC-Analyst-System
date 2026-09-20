"""Threat Intel: technique IDs named by the LLM must be corroborated by the MITRE similarity search."""

import asyncio
import importlib
from datetime import datetime
from types import SimpleNamespace

from app.models.incident import Alert, Severity

intel = importlib.import_module("app.agents.threat_intel_agent")


class NoToolsLLM:
    def bind_tools(self, _tools):
        return self

    async def ainvoke(self, _messages):
        return SimpleNamespace(content="", tool_calls=[])


def alert(rule, techniques):
    return Alert(timestamp=datetime.utcnow(), severity=Severity.HIGH, title="t", description="d",
                 detection_rule=rule, mitre_techniques=list(techniques))


def run(monkeypatch, alerts, hits):
    monkeypatch.setattr(intel, "get_llm", lambda *a, **k: NoToolsLLM())
    monkeypatch.setattr(intel, "search_mitre_techniques_raw", lambda *a, **k: hits)
    monkeypatch.setattr(intel, "get_mitre_technique_raw", lambda tid: {"id": tid, "name": "n", "tactic": "t", "description": "d", "detection_methods": []})
    state = {"alerts": alerts, "agent_execution_log": []}
    return asyncio.run(intel.threat_intel_agent(state))


def test_llm_technique_is_kept_only_if_the_search_corroborates_it(monkeypatch):
    a = alert("LLM-detected pattern", ["T1110", "T9999"])
    state = run(monkeypatch, [a], [{"id": "T1110", "score": 0.91}])
    assert a.mitre_techniques == ["T1110"]
    tagged = {t["technique_id"]: t["tagged"] for t in state["threat_intel"]["mitre_techniques"]}
    assert tagged == {"T1110": True, "T9999": False}


def test_a_weak_similarity_score_does_not_corroborate(monkeypatch):
    a = alert("LLM-detected pattern", ["T1110"])
    run(monkeypatch, [a], [{"id": "T1110", "score": 0.5}])
    assert a.mitre_techniques == []


def test_rule_generated_techniques_are_trusted(monkeypatch):
    a = alert("ATT&CK Rule: T1059.001", ["T1059.001"])
    run(monkeypatch, [a], [])
    assert a.mitre_techniques == ["T1059.001"]


def test_no_alerts_means_no_intel(monkeypatch):
    assert run(monkeypatch, [], [])["threat_intel"] == {}
