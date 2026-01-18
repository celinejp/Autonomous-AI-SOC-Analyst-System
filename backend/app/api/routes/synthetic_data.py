"""Synthetic Data Generation and Model Distillation endpoints."""

from fastapi import APIRouter, HTTPException, Depends, Body, BackgroundTasks
from typing import List, Dict, Any, Optional
import json
import asyncio
from pathlib import Path
from datetime import datetime

from sqlalchemy.ext.asyncio import AsyncSession
from app.database.postgres import get_db
from app.services.synthetic_data_service import (
    generate_synthetic_incident,
    generate_training_dataset,
    format_for_finetuning,
)
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)
router = APIRouter()


@router.post("/generate-single")
async def generate_single_synthetic(
    logs: List[str] = Body(..., description="Raw log entries to analyze"),
):
    """
    STEP 1: Generate single synthetic incident using Teacher Model.
    
    Teacher Model (Claude/LLM) analyzes logs and generates high-quality incident report.
    """
    try:
        result = await generate_synthetic_incident(logs)
        
        if not result:
            raise HTTPException(status_code=500, detail="Failed to generate synthetic data")
        
        return {
            "status": "success",
            "data": result,
            "message": "Synthetic incident generated successfully",
        }
    except Exception as e:
        logger.error(f"Synthetic generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-dataset")
async def generate_dataset(
    scenarios: List[Dict[str, Any]] = Body(..., description="List of attack scenarios with logs"),
    num_samples_per_scenario: int = Body(10, description="Number of samples per scenario"),
    format_type: str = Body("alpaca", description="Output format: alpaca, llama, or chatml"),
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
):
    """
    STEP 2: Generate complete training dataset.
    
    Creates training dataset from multiple scenarios:
    - Input: List of scenarios (each with logs)
    - Output: Formatted training samples for fine-tuning
    - Format: instruction/input/output pairs
    """
    try:
        # Generate training samples
        training_samples = await generate_training_dataset(scenarios, num_samples_per_scenario)
        
        if not training_samples:
            raise HTTPException(status_code=500, detail="Failed to generate training dataset")
        
        # Format for fine-tuning
        formatted_data = format_for_finetuning(training_samples, format_type)
        
        # Save to file
        output_dir = Path("backend/data/synthetic")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / f"training_dataset_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        output_file.write_text(formatted_data)
        
        return {
            "status": "success",
            "samples_generated": len(training_samples),
            "output_file": str(output_file),
            "format": format_type,
            "message": f"Generated {len(training_samples)} training samples",
            "preview": training_samples[:3] if len(training_samples) > 3 else training_samples,
        }
    except Exception as e:
        logger.error(f"Dataset generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/generate-from-fixtures")
async def generate_from_fixtures(
    num_samples_per_scenario: int = Body(5, description="Samples per scenario"),
):
    """
    Generate training dataset from test fixtures automatically.
    
    Uses backend/tests/fixtures/*.json files as scenarios.
    """
    try:
        from pathlib import Path
        import json
        
        fixtures_dir = Path("backend/tests/fixtures")
        scenarios = []
        
        # Load all fixture files
        for fixture_file in fixtures_dir.glob("*.json"):
            if "test_logs" in fixture_file.name:  # Skip test_logs.json
                continue
                
            with open(fixture_file) as f:
                data = json.load(f)
            
            scenarios.append({
                "name": data.get("description", fixture_file.stem),
                "logs": data.get("logs", []),
                "expected_detection": data.get("expected_detection", {}),
            })
        
        if not scenarios:
            raise HTTPException(status_code=404, detail="No fixture files found")
        
        # Generate dataset
        training_samples = await generate_training_dataset(scenarios, num_samples_per_scenario)
        
        # Format and save
        formatted_data = format_for_finetuning(training_samples, "alpaca")
        
        output_dir = Path("backend/data/synthetic")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_file = output_dir / f"fixture_dataset_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        output_file.write_text(formatted_data)
        
        return {
            "status": "success",
            "scenarios_used": len(scenarios),
            "samples_generated": len(training_samples),
            "output_file": str(output_file),
            "message": f"Generated {len(training_samples)} samples from {len(scenarios)} scenarios",
        }
    except Exception as e:
        logger.error(f"Fixture-based generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/compare-models")
async def compare_models(
    test_logs: List[str] = Body(..., description="Test logs to compare models"),
):
    """
    STEP 4: Compare Teacher vs Student model performance.
    
    Benchmarks:
    - Detection accuracy
    - Analysis speed
    - Cost per analysis
    - F1 Score
    """
    import time
    
    try:
        # Run teacher model (current LLM)
        teacher_start = time.time()
        teacher_result = await generate_synthetic_incident(test_logs)
        teacher_duration = time.time() - teacher_start
        
        # For now, student model is same as teacher (distillation not implemented yet)
        # TODO: Load fine-tuned student model when available
        student_start = time.time()
        student_result = await generate_synthetic_incident(test_logs)  # Placeholder
        student_duration = time.time() - student_start
        
        # Calculate metrics
        teacher_severity = teacher_result["output"]["severity"] if teacher_result else "unknown"
        student_severity = student_result["output"]["severity"] if student_result else "unknown"
        
        teacher_mitre = set(teacher_result["output"]["mitre_techniques"]) if teacher_result else set()
        student_mitre = set(student_result["output"]["mitre_techniques"]) if student_result else set()
        
        # Calculate accuracy
        severity_match = teacher_severity == student_severity
        mitre_accuracy = len(teacher_mitre & student_mitre) / len(teacher_mitre) if teacher_mitre else 0.0
        
        return {
            "status": "success",
            "teacher_model": {
                "provider": settings.llm_provider,
                "model": settings.llm_model,
                "severity": teacher_severity,
                "mitre_techniques": list(teacher_mitre),
                "duration_seconds": round(teacher_duration, 2),
                "cost_per_analysis": "TBD",  # Calculate based on tokens
            },
            "student_model": {
                "model": "distilled-soc-llama",  # Placeholder
                "severity": student_severity,
                "mitre_techniques": list(student_mitre),
                "duration_seconds": round(student_duration, 2),
                "cost_per_analysis": "$0.00",  # Local model is free
            },
            "comparison": {
                "severity_match": severity_match,
                "mitre_accuracy": round(mitre_accuracy, 2),
                "speedup": round(teacher_duration / student_duration, 2) if student_duration > 0 else 1.0,
                "cost_reduction": "100%",  # Local is free
            },
            "note": "Student model distillation not yet implemented. Using teacher model as placeholder.",
        }
    except Exception as e:
        logger.error(f"Model comparison error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/dataset-stats")
async def get_dataset_stats():
    """Get statistics about generated training datasets."""
    try:
        from pathlib import Path
        
        data_dir = Path("backend/data/synthetic")
        if not data_dir.exists():
            return {
                "status": "no_datasets",
                "message": "No datasets generated yet",
                "files": [],
            }
        
        datasets = []
        for dataset_file in data_dir.glob("*.json"):
            with open(dataset_file) as f:
                data = json.load(f)
                sample_count = len(data) if isinstance(data, list) else 1
            
            datasets.append({
                "filename": dataset_file.name,
                "samples": sample_count,
                "size_mb": round(dataset_file.stat().st_size / 1024 / 1024, 2),
                "created": datetime.fromtimestamp(dataset_file.stat().st_mtime).isoformat(),
            })
        
        return {
            "status": "success",
            "datasets": datasets,
            "total_samples": sum(d["samples"] for d in datasets),
        }
    except Exception as e:
        logger.error(f"Dataset stats error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

