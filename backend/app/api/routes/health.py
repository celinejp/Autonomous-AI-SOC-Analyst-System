"""Comprehensive health check endpoints."""

import asyncio
import time
from typing import Dict, Any, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.database.postgres import get_db
from app.database.redis_client import get_redis_client
from app.database.vector_store import get_qdrant_client
from app.core.llm_factory import get_llm
from app.core.config import settings
from app.core.logging import get_logger
from app.core.cache import cache_response
from app.orchestrator.langgraph_workflow import run_workflow_with_events
from app.models.agent_state import AgentState

logger = get_logger(__name__)
router = APIRouter()


class HealthCheckResult(BaseModel):
    """Health check result model."""
    status: str
    latency_ms: float = 0


class AgentHealthResult(BaseModel):
    """Agent health check result."""
    status: str
    duration_ms: float = 0
    error: str = None


class BasicHealthResponse(BaseModel):
    """Basic health check response."""
    status: str
    version: str
    timestamp: str
    checks: Dict[str, HealthCheckResult]


class DeepHealthResponse(BaseModel):
    """Deep health check response."""
    status: str
    checks: Dict[str, Any]
    total_duration_ms: float


class WorkflowTestResponse(BaseModel):
    """Workflow test response."""
    status: str
    agents: Dict[str, AgentHealthResult]
    incident_id: str = None
    error: str = None


async def check_database() -> HealthCheckResult:
    """Check database connection."""
    try:
        start = time.time()
        from app.database.postgres import engine
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        latency = (time.time() - start) * 1000
        return HealthCheckResult(status="pass", latency_ms=round(latency, 2))
    except Exception as e:
        logger.error(f"Database check failed: {e}")
        return HealthCheckResult(status="fail", latency_ms=0)


async def check_redis() -> HealthCheckResult:
    """Check Redis connection."""
    try:
        start = time.time()
        redis = get_redis_client()
        await redis.ping()
        latency = (time.time() - start) * 1000
        return HealthCheckResult(status="pass", latency_ms=round(latency, 2))
    except Exception as e:
        logger.error(f"Redis check failed: {e}")
        return HealthCheckResult(status="fail", latency_ms=0)


async def check_qdrant() -> HealthCheckResult:
    """Check Qdrant connection."""
    try:
        start = time.time()
        client = get_qdrant_client()
        collections = client.get_collections()
        latency = (time.time() - start) * 1000
        return HealthCheckResult(status="pass", latency_ms=round(latency, 2))
    except Exception as e:
        logger.error(f"Qdrant check failed: {e}")
        return HealthCheckResult(status="fail", latency_ms=0)


async def check_ollama() -> Dict[str, Any]:
    """Check Ollama/LLM availability."""
    try:
        start = time.time()
        llm = get_llm()
        
        # Try a simple invocation with timeout
        response = await asyncio.wait_for(
            llm.ainvoke("Say 'OK' if you are working."),
            timeout=10.0
        )
        
        latency = (time.time() - start) * 1000
        model_name = settings.llm_model or "unknown"
        
        return {
            "status": "pass",
            "latency_ms": round(latency, 2),
            "model": model_name,
            "provider": settings.llm_provider,
        }
    except asyncio.TimeoutError:
        return {"status": "fail", "error": "LLM timeout"}
    except Exception as e:
        logger.error(f"Ollama check failed: {e}")
        return {"status": "fail", "error": str(e)}


async def test_agent(agent_name: str, test_state: AgentState) -> AgentHealthResult:
    """Test a single agent with sample data."""
    try:
        start = time.time()
        
        # Import agent functions
        from app.agents.ingest_agent import ingest_agent
        from app.agents.detection_agent import detection_agent
        from app.agents.threat_intel_agent import threat_intel_agent
        from app.agents.analyst_agent import analyst_agent
        from app.agents.critic_agent import critic_agent
        from app.agents.response_planner import response_planner_agent
        
        agent_map = {
            "ingest_agent": ingest_agent,
            "detection_agent": detection_agent,
            "threat_intel_agent": threat_intel_agent,
            "analyst_agent": analyst_agent,
            "critic_agent": critic_agent,
            "response_planner": response_planner_agent,
        }
        
        agent_func = agent_map.get(agent_name)
        if not agent_func:
            return AgentHealthResult(
                status="fail",
                duration_ms=0,
                error=f"Unknown agent: {agent_name}"
            )
        
        # Run agent with timeout
        result = await asyncio.wait_for(
            agent_func(test_state.copy()),
            timeout=30.0
        )
        
        duration = (time.time() - start) * 1000
        
        return AgentHealthResult(
            status="pass",
            duration_ms=round(duration, 2)
        )
    except asyncio.TimeoutError:
        return AgentHealthResult(
            status="fail",
            duration_ms=0,
            error="Agent timeout (>30s)"
        )
    except Exception as e:
        logger.error(f"Agent {agent_name} test failed: {e}")
        return AgentHealthResult(
            status="fail",
            duration_ms=0,
            error=str(e)
        )


@router.get("/basic", response_model=BasicHealthResponse)
@cache_response(ttl=30, key_prefix="health:basic")
async def basic_health_check():
    """Basic health check - fast, cached for 30s."""
    db_check = await check_database()
    redis_check = await check_redis()
    qdrant_check = await check_qdrant()
    
    all_healthy = all(
        c.status == "pass" 
        for c in [db_check, redis_check, qdrant_check]
    )
    
    return BasicHealthResponse(
        status="healthy" if all_healthy else "degraded",
        version="1.0.0",
        timestamp=datetime.utcnow().isoformat(),
        checks={
            "database": db_check,
            "redis": redis_check,
            "qdrant": qdrant_check,
        }
    )


@router.get("/deep", response_model=DeepHealthResponse)
async def deep_health_check():
    """Deep health check - tests all agents with sample data."""
    start_time = time.time()
    
    # Infrastructure checks
    db_check = await check_database()
    redis_check = await check_redis()
    qdrant_check = await check_qdrant()
    ollama_check = await check_ollama()
    
    # Agent tests with sample data
    sample_logs = [
        "2024-01-15 10:30:00 AUTH FAILED user=admin src=192.168.1.100 dst=10.0.0.50 service=ssh",
        "2024-01-15 10:30:01 AUTH FAILED user=admin src=192.168.1.100 dst=10.0.0.50 service=ssh",
        "2024-01-15 10:30:02 AUTH SUCCESS user=admin src=192.168.1.100 dst=10.0.0.50 service=ssh"
    ]
    
    test_state: AgentState = {
        "logs": [],
        "raw_logs": sample_logs,
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
        "incident_id": "health-check-test",
    }
    
    # Test each agent
    agents = [
        "ingest_agent",
        "detection_agent",
        "threat_intel_agent",
        "analyst_agent",
        "critic_agent",
        "response_planner",
    ]
    
    agent_results = {}
    for agent_name in agents:
        result = await test_agent(agent_name, test_state)
        agent_results[agent_name] = result
    
    total_duration = (time.time() - start_time) * 1000
    
    # Determine overall status
    all_agents_pass = all(
        r.status == "pass" for r in agent_results.values()
    )
    all_infra_pass = all(
        c.status == "pass" 
        for c in [db_check, redis_check, qdrant_check]
    ) and ollama_check.get("status") == "pass"
    
    overall_status = "healthy" if (all_agents_pass and all_infra_pass) else "degraded"
    
    return DeepHealthResponse(
        status=overall_status,
        checks={
            "database": db_check.dict(),
            "redis": redis_check.dict(),
            "qdrant": qdrant_check.dict(),
            "ollama": ollama_check,
            "agents": {
                name: result.dict() 
                for name, result in agent_results.items()
            },
        },
        total_duration_ms=round(total_duration, 2)
    )


@router.post("/test-workflow", response_model=WorkflowTestResponse)
async def test_workflow(
    request: Dict[str, Any] = Body(...)
):
    """Test full workflow with provided logs."""
    try:
        logs = request.get("logs", [])
        if not logs:
            raise HTTPException(status_code=400, detail="logs field is required")
        
        import uuid
        incident_id = f"test-{uuid.uuid4()}"
        
        start_time = time.time()
        agent_durations = {}
        
        # Track agent execution
        async for event in run_workflow_with_events(logs, incident_id):
            if event.get("type") == "agent_start":
                agent = event.get("agent")
                agent_start = time.time()
            elif event.get("type") == "agent_complete":
                agent = event.get("agent")
                if "agent_start" in locals():
                    duration = (time.time() - agent_start) * 1000
                    agent_durations[agent] = duration
            elif event.get("type") == "complete":
                # Workflow completed
                break
            elif event.get("type") == "error":
                return WorkflowTestResponse(
                    status="fail",
                    agents={},
                    error=event.get("error", "Unknown error")
                )
        
        total_duration = (time.time() - start_time) * 1000
        
        # Build agent results
        agent_results = {}
        for agent_name in [
            "ingest", "detect", "enrich", "analyze", 
            "critique", "plan_response"
        ]:
            duration = agent_durations.get(agent_name, 0)
            agent_results[agent_name] = AgentHealthResult(
                status="pass" if duration > 0 else "fail",
                duration_ms=round(duration, 2)
            )
        
        return WorkflowTestResponse(
            status="pass",
            agents=agent_results,
            incident_id=incident_id,
        )
        
    except Exception as e:
        logger.error(f"Workflow test failed: {e}")
        return WorkflowTestResponse(
            status="fail",
            agents={},
            error=str(e)
        )
