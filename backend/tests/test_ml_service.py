"""Tests for ML anomaly detection service."""

import pytest
from datetime import datetime, timedelta
from app.services.ml_service import AnomalyDetector
from app.models.log_entry import LogEntry, LogSource


def test_anomaly_detector_initialization():
    """Test anomaly detector initializes correctly."""
    detector = AnomalyDetector()
    assert detector.baseline_established == False
    assert detector.baseline_stats == {}


def test_establish_baseline():
    """Test baseline establishment."""
    detector = AnomalyDetector()
    
    logs = [
        LogEntry(
            timestamp=datetime.utcnow() - timedelta(hours=1),
            source_ip="192.168.1.1",
            action="login",
            status="success",
            log_source=LogSource.AUTH,
            raw_log="test",
        )
        for _ in range(10)
    ]
    
    baseline = detector.establish_baseline(logs)
    
    assert detector.baseline_established == True
    assert baseline["total_logs"] == 10
    assert "192.168.1.1" in baseline["source_ip_counts"]


def test_detect_anomalies():
    """Test anomaly detection."""
    detector = AnomalyDetector()
    
    # Establish baseline
    baseline_logs = [
        LogEntry(
            timestamp=datetime.utcnow() - timedelta(hours=1),
            source_ip="192.168.1.1",
            action="login",
            status="success",
            log_source=LogSource.AUTH,
            raw_log="test",
        )
        for _ in range(10)
    ]
    detector.establish_baseline(baseline_logs)
    
    # Test logs with anomalies
    test_logs = [
        LogEntry(
            timestamp=datetime.utcnow(),
            source_ip="185.1.1.1",  # New IP
            action="login_failed",
            status="failure",
            log_source=LogSource.AUTH,
            raw_log="test",
        )
        for _ in range(20)  # Many failed logins
    ]
    
    anomalies = detector.detect_anomalies(test_logs)
    
    assert len(anomalies) > 0
    assert any(a["type"] == "brute_force" for a in anomalies)

