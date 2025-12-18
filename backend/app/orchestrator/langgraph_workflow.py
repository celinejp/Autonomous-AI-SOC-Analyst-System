"""LangGraph workflow for SOC analyst agents."""

from typing import AsyncGenerator, Dict, Any
import uuid
from datetime import datetime

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

from app.models.agent_state import AgentState
from app.agents.ingest_agent import ingest_agent
from app.agents.detection_agent import detection_agent
from app.agents.threat_intel_agent import threat_intel_agent
from app.agents.analyst_agent import analyst_agent
from app.agents.critic_agent import critic_agent
from app.agents.response_planner import response_planner_agent
from app.core.logging import get_logger

logger = get_logger(__name__)


def should_continue_reflection(state: AgentState) -> str:
    """Determine if reflection loop should continue."""
    needs_revision = state.get("needs_revision", False)
    iteration = state.get("iteration", 0)
    confidence = state.get("confidence", 0.0)
    
    # Continue if revision needed, confidence low, and within iteration limit
    if needs_revision and iteration < 3 and confidence < 0.7:
        logger.info(
            "Reflection loop continuing",
            iteration=iteration,
            confidence=confidence,
            needs_revision=needs_revision,
        )
        return "continue"
    
    logger.info(
        "Reflection loop ending",
        iteration=iteration,
        confidence=confidence,
        needs_revision=needs_revision,
    )
    return "end"


_workflow_app = None


def create_workflow():
    """Create and compile the LangGraph workflow."""
    global _workflow_app
    
    if _workflow_app is not None:
        return _workflow_app
    
    # Initialize state graph
    workflow = StateGraph(AgentState)

    # Add nodes (agents)
    workflow.add_node("ingest", ingest_agent)
    workflow.add_node("detect", detection_agent)
    workflow.add_node("threat_intel", threat_intel_agent)
    workflow.add_node("analyze", analyst_agent)
    workflow.add_node("critique", critic_agent)
    workflow.add_node("plan_response", response_planner_agent)

    # Add edges (linear flow)
    workflow.add_edge("ingest", "detect")
    workflow.add_edge("detect", "threat_intel")
    workflow.add_edge("threat_intel", "analyze")
    workflow.add_edge("analyze", "critique")

    # Conditional edge for reflection loop
    workflow.add_conditional_edges(
        "critique",
        should_continue_reflection,
        {
            "continue": "analyze",  # Go back to analyst for revision
            "end": "plan_response",  # Proceed to response planning
        },
    )

    workflow.add_edge("plan_response", END)

    # Set entry point
    workflow.set_entry_point("ingest")

    # Compile with checkpointing for state management
    memory = MemorySaver()
    _workflow_app = workflow.compile(checkpointer=memory)

    return _workflow_app


async def run_workflow(
    raw_logs: list[str],
    incident_id: str = None,
    stream: bool = False,
) -> AsyncGenerator[Dict[str, Any], None]:
    """Run the workflow and optionally stream updates."""
    workflow_app = create_workflow()
    
    if incident_id is None:
        incident_id = str(uuid.uuid4())

    # Initialize state
    initial_state: AgentState = {
        "logs": [],
        "raw_logs": raw_logs,
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
        "incident_id": incident_id,
    }

    config = {"configurable": {"thread_id": incident_id}}

    try:
        if stream:
            # Stream workflow execution
            async for event in workflow_app.astream(initial_state, config=config, stream_mode="values"):
                yield {
                    "type": "state_update",
                    "data": event,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            
            # Get final state
            final_state = await workflow_app.ainvoke(initial_state, config=config)
            yield {
                "type": "complete",
                "data": final_state,
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
            # Run to completion
            final_state = await workflow_app.ainvoke(initial_state, config=config)
            yield {
                "type": "complete",
                "data": final_state,
                "timestamp": datetime.utcnow().isoformat(),
            }
    except Exception as e:
        logger.error("Workflow execution error", error=str(e), incident_id=incident_id)
        yield {
            "type": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }
        raise

