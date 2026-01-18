"""Synthetic Data Generation Service - Teacher Model (Claude/LLM) generates high-quality training data."""

import json
from typing import List, Dict, Any
from datetime import datetime
import asyncio

from app.core.llm_factory import get_llm
from app.core.config import settings
from app.orchestrator.langgraph_workflow import run_workflow
from app.models.agent_state import AgentState
from app.core.logging import get_logger

logger = get_logger(__name__)


async def generate_synthetic_incident(teacher_logs: List[str]) -> Dict[str, Any]:
    """
    STEP 1: Teacher Model (Claude/LLM) analyzes logs and generates high-quality incident report.
    
    This is the "teacher" in knowledge distillation - generates perfect outputs.
    """
    try:
        # Use teacher model (preferably Claude, fallback to configured LLM)
        # For now, use configured LLM (can be switched to Claude if available)
        teacher_llm = get_llm(temperature=0.1)  # Low temperature for consistent output
        
        # Run full workflow to get complete analysis
        incident_id = f"teacher_{datetime.utcnow().timestamp()}"
        
        # Run workflow and get final state
        final_state = None
        async for event in run_workflow(teacher_logs, incident_id, stream=False):
            if event.get("type") == "complete":
                final_state = event.get("data")
                break
        
        # If no complete event, get last state
        if not final_state:
            # Try one more time to get state
            async for event in run_workflow(teacher_logs, incident_id, stream=False):
                final_state = event.get("data")
                if final_state:
                    break
        
        if not final_state:
            logger.warning("Failed to get final state from workflow")
            return None
        
        # Extract teacher's analysis
        alerts = final_state.get("alerts", [])
        incident_report = final_state.get("incident_report")
        threat_intel = final_state.get("threat_intel", {})
        response_plan = final_state.get("response_plan")
        
        # Determine severity
        severity = "low"
        if alerts:
            severities = [a.severity.value for a in alerts]
            if "critical" in severities:
                severity = "critical"
            elif "high" in severities:
                severity = "high"
            elif "medium" in severities:
                severity = "medium"
        
        # Extract MITRE techniques
        mitre_techniques = []
        for alert in alerts:
            mitre_techniques.extend(alert.mitre_techniques or [])
        
        # Get from threat intel too
        threat_mitre = threat_intel.get("mitre_techniques", [])
        for tech in threat_mitre:
            if isinstance(tech, dict):
                mitre_techniques.append(tech.get("technique_id", ""))
            elif isinstance(tech, str):
                mitre_techniques.append(tech)
        
        mitre_techniques = list(set(filter(None, mitre_techniques)))
        
        return {
            "input_logs": teacher_logs,
            "output": {
                "severity": severity,
                "mitre_techniques": mitre_techniques,
                "alerts_count": len(alerts),
                "alerts": [
                    {
                        "title": a.title,
                        "severity": a.severity.value,
                        "description": a.description,
                        "mitre_techniques": a.mitre_techniques or [],
                    }
                    for a in alerts
                ],
                "executive_summary": incident_report.executive_summary if incident_report else "",
                "technical_findings": incident_report.technical_findings if incident_report else "",
                "root_cause": incident_report.root_cause if incident_report else "",
                "timeline": incident_report.timeline if incident_report else [],
                "recommendations": [
                    action.action for action in (response_plan.containment_actions or []) if response_plan
                ],
                "confidence_score": final_state.get("confidence", 0.0),
            },
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "teacher_model": settings.llm_provider,
                "agent_execution_log": final_state.get("agent_execution_log", []),
            },
        }
    except Exception as e:
        logger.error(f"Synthetic data generation failed: {e}")
        return None


async def generate_training_dataset(scenarios: List[Dict[str, Any]], num_samples_per_scenario: int = 10) -> List[Dict[str, Any]]:
    """
    STEP 2: Generate training dataset from multiple scenarios.
    
    Format: {"instruction": "...", "input": "...", "output": "..."}
    1000 examples × 6 agents = 6000 training samples
    """
    training_samples = []
    
    for scenario in scenarios:
        scenario_name = scenario.get("name", "unknown")
        scenario_logs = scenario.get("logs", [])
        
        logger.info(f"Generating {num_samples_per_scenario} samples for scenario: {scenario_name}")
        
        # Generate multiple variations
        for i in range(num_samples_per_scenario):
            try:
                # Use base logs, can add slight variations
                synthetic = await generate_synthetic_incident(scenario_logs)
                
                if synthetic:
                    # Format for fine-tuning (instruction-following format)
                    training_sample = {
                        "instruction": "Analyze these security logs and identify threats. Provide severity, MITRE techniques, and recommendations.",
                        "input": "\n".join(synthetic["input_logs"]),
                        "output": json.dumps(synthetic["output"], indent=2),
                        "metadata": {
                            "scenario": scenario_name,
                            "sample_id": i,
                            **synthetic["metadata"],
                        },
                    }
                    training_samples.append(training_sample)
                
                # Rate limiting
                await asyncio.sleep(0.5)
                
            except Exception as e:
                logger.error(f"Failed to generate sample {i} for {scenario_name}: {e}")
                continue
    
    logger.info(f"Generated {len(training_samples)} training samples")
    return training_samples


def format_for_finetuning(training_samples: List[Dict[str, Any]], format_type: str = "alpaca") -> str:
    """
    Format training samples for different fine-tuning formats.
    
    Formats:
    - alpaca: {"instruction": "...", "input": "...", "output": "..."}
    - llama: {"text": "### Instruction:\n...\n### Input:\n...\n### Response:\n..."}
    - chatml: [{"role": "user", "content": "..."}, {"role": "assistant", "content": "..."}]
    """
    if format_type == "alpaca":
        return json.dumps(training_samples, indent=2)
    elif format_type == "llama":
        formatted = []
        for sample in training_samples:
            text = f"""### Instruction:
{sample['instruction']}

### Input:
{sample['input']}

### Response:
{sample['output']}"""
            formatted.append({"text": text})
        return json.dumps(formatted, indent=2)
    elif format_type == "chatml":
        formatted = []
        for sample in training_samples:
            formatted.append({
                "messages": [
                    {"role": "user", "content": f"{sample['instruction']}\n\nInput:\n{sample['input']}"},
                    {"role": "assistant", "content": sample['output']},
                ]
            })
        return json.dumps(formatted, indent=2)
    
    return json.dumps(training_samples, indent=2)

