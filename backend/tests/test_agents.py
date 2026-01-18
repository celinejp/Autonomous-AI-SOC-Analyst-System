"""Tests for agent functionality."""

import pytest
from datetime import datetime
from app.models.agent_state import AgentState
from app.agents.ingest_agent import ingest_agent
from app.models.log_entry import LogEntry, LogSource


@pytest.mark.asyncio
async def test_ingest_agent():
    """Test ingest agent processes logs correctly."""
    state: AgentState = {
        "logs": [],
        "raw_logs": [
            '{"timestamp": "2024-01-01T12:00:00Z", "source_ip": "192.168.1.1", "action": "login", "status": "success"}',
        ],
        "alerts": [],
        "threat_intel": {},
        "incident_report": None,
        "response_plan": None,
        "confidence": 0.0,
        "iteration": 0,
        "needs_revision": False,
        "critique_feedback": None,
        "messages": [],
        "agent_execution_log": [],
        "incident_id": None,
    }
    
    result = await ingest_agent(state)
    
    assert len(result["logs"]) > 0
    assert result["logs"][0].source_ip == "192.168.1.1"


@pytest.mark.asyncio
async def test_detection_agent_empty_logs():
    """Test detection agent handles empty logs."""
    from app.agents.detection_agent import detection_agent
    
    state: AgentState = {
        "logs": [],
        "raw_logs": [],
        "alerts": [],
        "threat_intel": {},
        "incident_report": None,
        "response_plan": None,
        "confidence": 0.0,
        "iteration": 0,
        "needs_revision": False,
        "critique_feedback": None,
        "messages": [],
        "agent_execution_log": [],
        "incident_id": None,
    }
    
    result = await detection_agent(state)
    
    assert result["alerts"] == []

