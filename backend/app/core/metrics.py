"""Quality metrics calculation for AI agent outputs."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from datetime import datetime


class IncidentMetrics(BaseModel):
    """Metrics for a single incident analysis."""
    
    incident_id: str
    calculated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Core metrics (0-1 scale)
    detection_confidence: float = Field(ge=0, le=1, description="AI confidence in detection")
    mitre_accuracy: float = Field(ge=0, le=1, description="MITRE technique mapping accuracy")
    false_positive_probability: float = Field(ge=0, le=1, description="Likelihood of false positive")
    analysis_completeness: float = Field(ge=0, le=1, description="Required fields completion rate")
    response_quality: float = Field(ge=0, le=1, description="Actionability of recommendations")
    
    # Aggregate score
    overall_quality: float = Field(ge=0, le=1, description="Weighted average of all metrics")
    
    # Details
    missing_fields: List[str] = Field(default_factory=list)
    matched_techniques: List[str] = Field(default_factory=list)
    missed_techniques: List[str] = Field(default_factory=list)
    extra_techniques: List[str] = Field(default_factory=list)


class AggregateMetrics(BaseModel):
    """Aggregated system-wide metrics."""
    
    period_start: datetime
    period_end: datetime
    total_incidents: int
    
    # Averages
    avg_accuracy: float
    avg_precision: float
    avg_recall: float
    avg_f1_score: float
    avg_confidence: float
    
    # Rates
    true_positive_rate: float
    false_positive_rate: float
    false_negative_rate: float
    
    # By agent
    agent_performance: Dict[str, float] = Field(default_factory=dict)


# Required fields for completeness check
REQUIRED_INCIDENT_FIELDS = [
    "alerts",
    "mitre_techniques", 
    "incident_report",
    "response_plan",
    "confidence_score",
]

REQUIRED_REPORT_FIELDS = [
    "executive_summary",
    "technical_findings",
    "root_cause",
    "affected_assets",
    "impact_assessment",
]

REQUIRED_RESPONSE_FIELDS = [
    "containment_actions",
    "investigation_steps",
    "remediation_actions",
]


def calculate_detection_confidence(incident: Dict[str, Any]) -> float:
    """Calculate detection confidence from incident data."""
    confidence = incident.get("confidence_score", 0.0)
    
    # Boost confidence if multiple corroborating signals
    alerts = incident.get("alerts", [])
    techniques = incident.get("mitre_techniques", [])
    
    if len(alerts) > 1:
        confidence = min(1.0, confidence + 0.05)
    if len(techniques) > 0:
        confidence = min(1.0, confidence + 0.05)
    
    # Reduce confidence if iteration count is high (needed revisions)
    iteration = incident.get("iteration", 0)
    if iteration > 2:
        confidence = max(0.0, confidence - 0.1)
    
    return round(confidence, 3)


def calculate_mitre_accuracy(
    detected_techniques: List[str],
    ground_truth_techniques: List[str]
) -> tuple[float, List[str], List[str], List[str]]:
    """Calculate MITRE technique mapping accuracy."""
    if not ground_truth_techniques:
        return 1.0 if not detected_techniques else 0.5, [], [], detected_techniques
    
    detected_set = set(t.upper() for t in detected_techniques)
    truth_set = set(t.upper() for t in ground_truth_techniques)
    
    matched = detected_set & truth_set
    missed = truth_set - detected_set
    extra = detected_set - truth_set
    
    # Jaccard similarity
    union = detected_set | truth_set
    accuracy = len(matched) / len(union) if union else 1.0
    
    return (
        round(accuracy, 3),
        list(matched),
        list(missed),
        list(extra)
    )


def calculate_false_positive_probability(incident: Dict[str, Any]) -> float:
    """Estimate false positive probability."""
    fp_prob = 0.5  # Start neutral
    
    # Lower FP probability with more evidence
    alerts = incident.get("alerts", [])
    if len(alerts) >= 3:
        fp_prob -= 0.2
    elif len(alerts) >= 1:
        fp_prob -= 0.1
    
    # MITRE mapping reduces FP probability
    techniques = incident.get("mitre_techniques", [])
    if len(techniques) >= 2:
        fp_prob -= 0.15
    elif len(techniques) >= 1:
        fp_prob -= 0.1
    
    # High confidence reduces FP probability
    confidence = incident.get("confidence_score", 0.5)
    if confidence > 0.8:
        fp_prob -= 0.2
    elif confidence > 0.6:
        fp_prob -= 0.1
    
    # Severity affects FP probability (higher severity = more scrutiny needed)
    severity = str(incident.get("severity", "")).lower()
    if severity in ["critical", "high"]:
        fp_prob += 0.05  # Slightly higher FP risk for high severity calls
    
    return round(max(0.0, min(1.0, fp_prob)), 3)


def calculate_analysis_completeness(incident: Dict[str, Any]) -> tuple[float, List[str]]:
    """Check if all required fields are present and populated."""
    missing = []
    total_fields = len(REQUIRED_INCIDENT_FIELDS)
    present = 0
    
    for field in REQUIRED_INCIDENT_FIELDS:
        value = incident.get(field)
        if value is not None and value != [] and value != {}:
            present += 1
        else:
            missing.append(field)
    
    # Check report fields
    report = incident.get("incident_report") or incident.get("report", {})
    if report:
        for field in REQUIRED_REPORT_FIELDS:
            total_fields += 1
            value = report.get(field) if isinstance(report, dict) else getattr(report, field, None)
            if value:
                present += 1
            else:
                missing.append(f"report.{field}")
    
    # Check response plan fields
    plan = incident.get("response_plan", {})
    if plan:
        for field in REQUIRED_RESPONSE_FIELDS:
            total_fields += 1
            value = plan.get(field) if isinstance(plan, dict) else getattr(plan, field, None)
            if value and len(value) > 0:
                present += 1
            else:
                missing.append(f"response_plan.{field}")
    
    completeness = present / total_fields if total_fields > 0 else 0.0
    return round(completeness, 3), missing


def calculate_response_quality(incident: Dict[str, Any]) -> float:
    """Evaluate quality/actionability of response recommendations."""
    score = 0.0
    max_score = 0.0
    
    plan = incident.get("response_plan", {})
    if not plan:
        return 0.0
    
    # Check containment actions
    containment = plan.get("containment_actions", [])
    max_score += 1.0
    if containment:
        # Score based on specificity
        score += min(1.0, len(containment) * 0.25)
    
    # Check investigation steps
    investigation = plan.get("investigation_steps", [])
    max_score += 1.0
    if investigation:
        score += min(1.0, len(investigation) * 0.2)
    
    # Check remediation actions
    remediation = plan.get("remediation_actions", [])
    max_score += 1.0
    if remediation:
        score += min(1.0, len(remediation) * 0.25)
    
    # Check long-term improvements
    improvements = plan.get("long_term_improvements", [])
    max_score += 0.5
    if improvements:
        score += min(0.5, len(improvements) * 0.1)
    
    return round(score / max_score if max_score > 0 else 0.0, 3)


def calculate_incident_metrics(
    incident: Dict[str, Any],
    ground_truth_techniques: Optional[List[str]] = None
) -> IncidentMetrics:
    """Calculate all metrics for an incident."""
    incident_id = incident.get("incident_id") or incident.get("id", "unknown")
    
    # Detection confidence
    detection_confidence = calculate_detection_confidence(incident)
    
    # MITRE accuracy
    detected_techniques = []
    for tech in incident.get("mitre_techniques", []):
        if isinstance(tech, dict):
            detected_techniques.append(tech.get("technique_id", ""))
        else:
            detected_techniques.append(str(tech))
    
    if ground_truth_techniques:
        mitre_acc, matched, missed, extra = calculate_mitre_accuracy(
            detected_techniques, ground_truth_techniques
        )
    else:
        mitre_acc = 1.0 if detected_techniques else 0.5
        matched, missed, extra = detected_techniques, [], []
    
    # False positive probability
    fp_prob = calculate_false_positive_probability(incident)
    
    # Completeness
    completeness, missing_fields = calculate_analysis_completeness(incident)
    
    # Response quality
    response_quality = calculate_response_quality(incident)
    
    # Overall quality (weighted average)
    overall = (
        detection_confidence * 0.25 +
        mitre_acc * 0.20 +
        (1 - fp_prob) * 0.15 +
        completeness * 0.25 +
        response_quality * 0.15
    )
    
    return IncidentMetrics(
        incident_id=incident_id,
        detection_confidence=detection_confidence,
        mitre_accuracy=mitre_acc,
        false_positive_probability=fp_prob,
        analysis_completeness=completeness,
        response_quality=response_quality,
        overall_quality=round(overall, 3),
        missing_fields=missing_fields,
        matched_techniques=matched,
        missed_techniques=missed,
        extra_techniques=extra,
    )
