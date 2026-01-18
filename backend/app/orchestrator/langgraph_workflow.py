"""LangGraph workflow for SOC analyst agents with streaming support."""

from typing import AsyncGenerator, Dict, Any, Callable
import uuid
from datetime import datetime
import asyncio

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
_workflow_app_streaming = None


def create_workflow():
    """Create and compile the LangGraph workflow."""
    global _workflow_app
    
    if _workflow_app is not None:
        return _workflow_app
    
    workflow = StateGraph(AgentState)

    workflow.add_node("ingest", ingest_agent)
    workflow.add_node("detect", detection_agent)
    workflow.add_node("enrich", threat_intel_agent)
    workflow.add_node("analyze", analyst_agent)
    workflow.add_node("critique", critic_agent)
    workflow.add_node("plan_response", response_planner_agent)

    workflow.add_edge("ingest", "detect")
    workflow.add_edge("detect", "enrich")
    workflow.add_edge("enrich", "analyze")
    workflow.add_edge("analyze", "critique")

    workflow.add_conditional_edges(
        "critique",
        should_continue_reflection,
        {
            "continue": "analyze",
            "end": "plan_response",
        },
    )

    workflow.add_edge("plan_response", END)
    workflow.set_entry_point("ingest")

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
            async for event in workflow_app.astream(initial_state, config=config, stream_mode="values"):
                yield {
                    "type": "state_update",
                    "data": event,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            
            final_state = await workflow_app.ainvoke(initial_state, config=config)
            yield {
                "type": "complete",
                "data": final_state,
                "timestamp": datetime.utcnow().isoformat(),
            }
        else:
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


async def run_workflow_with_events(
    raw_logs: list[str],
    incident_id: str = None,
) -> AsyncGenerator[Dict[str, Any], None]:
    """Run workflow with detailed agent-level events for SSE streaming."""
    workflow_app = create_workflow()
    
    if incident_id is None:
        incident_id = str(uuid.uuid4())

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
    
    # Track which agents have been seen
    seen_agents = set()
    last_state = initial_state.copy()
    
    try:
        # Use updates mode to get node-level events
        async for event in workflow_app.astream(
            initial_state, 
            config=config, 
            stream_mode="updates"
        ):
            # event is a dict with node name as key
            for node_name, node_output in event.items():
                if node_name == "__end__":
                    continue
                
                # Emit agent_start if first time seeing this agent
                if node_name not in seen_agents:
                    seen_agents.add(node_name)
                    yield {
                        "type": "agent_start",
                        "agent": node_name,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                
                # Merge output into state
                if isinstance(node_output, dict):
                    last_state.update(node_output)
                
                # Emit agent output with relevant data
                yield {
                    "type": "agent_output",
                    "agent": node_name,
                    "data": serialize_state_for_stream(last_state),
                    "timestamp": datetime.utcnow().isoformat(),
                }
                
                # Emit agent complete
                yield {
                    "type": "agent_complete",
                    "agent": node_name,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                
                # Small delay to allow frontend to process
                await asyncio.sleep(0.1)
        
        # Get final state
        final_state = await workflow_app.aget_state(config)
        final_values = final_state.values if hasattr(final_state, 'values') else last_state
        
        yield {
            "type": "complete",
            "data": serialize_state_for_stream(final_values),
            "timestamp": datetime.utcnow().isoformat(),
        }
        
    except Exception as e:
        logger.error("Workflow execution error", error=str(e), incident_id=incident_id)
        yield {
            "type": "error",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat(),
        }


def serialize_state_for_stream(state: Dict[str, Any]) -> Dict[str, Any]:
    """Serialize state for JSON streaming, handling non-serializable objects."""
    result = {}
    
    # Safe keys to include
    safe_keys = [
        "logs", "alerts", "threat_intel", "confidence", 
        "iteration", "needs_revision", "incident_id"
    ]
    
    for key in safe_keys:
        if key in state:
            value = state[key]
            if isinstance(value, (str, int, float, bool, type(None))):
                result[key] = value
            elif isinstance(value, list):
                result[key] = [serialize_item(item) for item in value[:20]]  # Limit list size
            elif isinstance(value, dict):
                result[key] = {k: serialize_item(v) for k, v in list(value.items())[:20]}
    
    # Handle special objects
    if "incident_report" in state and state["incident_report"]:
        report = state["incident_report"]
        if hasattr(report, "model_dump"):
            result["incident_report"] = report.model_dump()
        elif isinstance(report, dict):
            result["incident_report"] = report
    
    if "response_plan" in state and state["response_plan"]:
        plan = state["response_plan"]
        if hasattr(plan, "model_dump"):
            result["response_plan"] = plan.model_dump()
        elif isinstance(plan, dict):
            result["response_plan"] = plan
    
    # Include mitre_techniques if present
    if "mitre_techniques" in state:
        techniques = state["mitre_techniques"]
        if isinstance(techniques, list):
            result["mitre_techniques"] = [serialize_item(t) for t in techniques[:10]]
    
    return result


def serialize_item(item: Any) -> Any:
    """Serialize a single item for JSON."""
    if isinstance(item, (str, int, float, bool, type(None))):
        return item
    elif hasattr(item, "model_dump"):
        return item.model_dump()
    elif hasattr(item, "__dict__"):
        return {k: v for k, v in item.__dict__.items() if not k.startswith("_")}
    elif isinstance(item, dict):
        return item
    elif isinstance(item, list):
        return [serialize_item(i) for i in item[:10]]
    else:
        return str(item)
