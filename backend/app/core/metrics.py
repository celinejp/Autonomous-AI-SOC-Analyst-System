"""Quality metrics calculation for AI agent outputs."""

from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field
from datetime import datetime
import json


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


class ValidationResult(BaseModel):
    """Result of validating against ground truth."""
    
    incident_id: str
    ground_truth_id: str
    validated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Classification metrics
    accuracy: float = Field(ge=0, le=1)
    precision: float = Field(ge=0, le=1)
    recall: float = Field(ge=0, le=1)
    f1_score: float = Field(ge=0, le=1)
    
    # Domain-specific metrics
    mitre_accuracy: float = Field(ge=0, le=1)
    severity_accuracy: float = Field(ge=0, le=1)
    ioc_recall: float = Field(ge=0, le=1)
    confidence_score: float = Field(ge=0, le=1)
    
    # Details
    details: Dict[str, Any] = Field(default_factory=dict)


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


def validate_against_ground_truth(
    incident: Dict[str, Any],
    ground_truth: Dict[str, Any]
) -> ValidationResult:
    """Validate incident analysis against labeled ground truth."""
    incident_id = incident.get("incident_id") or incident.get("id", "unknown")
    gt_id = ground_truth.get("id", "unknown")
    
    # Classification metrics
    predicted_positive = incident.get("severity", "").lower() in ["high", "critical", "medium"]
    actual_positive = ground_truth.get("is_true_positive", True)
    
    # For single sample, calculate binary metrics
    tp = 1 if predicted_positive and actual_positive else 0
    fp = 1 if predicted_positive and not actual_positive else 0
    tn = 1 if not predicted_positive and not actual_positive else 0
    fn = 1 if not predicted_positive and actual_positive else 0
    
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
    
    # MITRE accuracy
    detected_techniques = [
        t.get("technique_id", t) if isinstance(t, dict) else str(t)
        for t in incident.get("mitre_techniques", [])
    ]
    gt_techniques = ground_truth.get("mitre_techniques", [])
    mitre_acc, _, _, _ = calculate_mitre_accuracy(detected_techniques, gt_techniques)
    
    # Severity accuracy
    predicted_severity = incident.get("severity", "medium").lower()
    actual_severity = ground_truth.get("severity", "medium").lower()
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    pred_val = severity_map.get(predicted_severity, 2)
    actual_val = severity_map.get(actual_severity, 2)
    severity_accuracy = 1.0 - abs(pred_val - actual_val) / 3.0
    
    # IoC recall
    gt_iocs = set(ground_truth.get("iocs", {}).get("ips", []))
    detected_iocs = set()
    for alert in incident.get("alerts", []):
        evidence = alert.get("evidence", [])
        for e in evidence:
            if isinstance(e, str) and "." in e:
                detected_iocs.add(e)
    ioc_recall = len(gt_iocs & detected_iocs) / len(gt_iocs) if gt_iocs else 1.0
    
    # Confidence score
    confidence = incident.get("confidence_score", 0.5)
    
    return ValidationResult(
        incident_id=incident_id,
        ground_truth_id=gt_id,
        accuracy=round(accuracy, 3),
        precision=round(precision, 3),
        recall=round(recall, 3),
        f1_score=round(f1, 3),
        mitre_accuracy=mitre_acc,
        severity_accuracy=round(severity_accuracy, 3),
        ioc_recall=round(ioc_recall, 3),
        confidence_score=round(confidence, 3),
        details={
            "predicted_positive": predicted_positive,
            "actual_positive": actual_positive,
            "detected_techniques": detected_techniques,
            "expected_techniques": gt_techniques,
        }
    )


def calculate_aggregate_metrics(
    validation_results: List[ValidationResult],
    period_start: datetime,
    period_end: datetime
) -> AggregateMetrics:
    """Calculate aggregate metrics from multiple validation results."""
    if not validation_results:
        return AggregateMetrics(
            period_start=period_start,
            period_end=period_end,
            total_incidents=0,
            avg_accuracy=0, avg_precision=0, avg_recall=0,
            avg_f1_score=0, avg_confidence=0,
            true_positive_rate=0, false_positive_rate=0, false_negative_rate=0,
        )
    
    n = len(validation_results)
    
    # Calculate averages
    avg_accuracy = sum(r.accuracy for r in validation_results) / n
    avg_precision = sum(r.precision for r in validation_results) / n
    avg_recall = sum(r.recall for r in validation_results) / n
    avg_f1 = sum(r.f1_score for r in validation_results) / n
    avg_confidence = sum(r.confidence_score for r in validation_results) / n
    
    # Calculate rates
    tp = sum(1 for r in validation_results if r.details.get("predicted_positive") and r.details.get("actual_positive"))
    fp = sum(1 for r in validation_results if r.details.get("predicted_positive") and not r.details.get("actual_positive"))
    fn = sum(1 for r in validation_results if not r.details.get("predicted_positive") and r.details.get("actual_positive"))
    tn = sum(1 for r in validation_results if not r.details.get("predicted_positive") and not r.details.get("actual_positive"))
    
    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
    
    return AggregateMetrics(
        period_start=period_start,
        period_end=period_end,
        total_incidents=n,
        avg_accuracy=round(avg_accuracy, 3),
        avg_precision=round(avg_precision, 3),
        avg_recall=round(avg_recall, 3),
        avg_f1_score=round(avg_f1, 3),
        avg_confidence=round(avg_confidence, 3),
        true_positive_rate=round(tpr, 3),
        false_positive_rate=round(fpr, 3),
        false_negative_rate=round(fnr, 3),
    )

