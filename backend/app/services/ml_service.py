"""Machine Learning Anomaly Detection Service."""

from typing import List, Dict, Any, Optional
import numpy as np
from datetime import datetime, timedelta

from app.core.logging import get_logger
from app.models.log_entry import LogEntry

logger = get_logger(__name__)


class AnomalyDetector:
    """ML-based anomaly detection for security logs."""

    def __init__(self):
        """Initialize anomaly detector."""
        self.baseline_established = False
        self.baseline_stats = {}
        logger.info("Anomaly detector initialized")

    def establish_baseline(self, logs: List[LogEntry], window_hours: int = 24) -> Dict[str, Any]:
        """Establish baseline statistics from historical logs.
        
        Args:
            logs: List of log entries
            window_hours: Time window for baseline calculation
            
        Returns:
            Baseline statistics dictionary
        """
        if not logs:
            return {}
        
        # Calculate baseline metrics
        source_ips = {}
        destination_ips = {}
        actions = {}
        users = {}
        
        cutoff_time = datetime.utcnow() - timedelta(hours=window_hours)
        recent_logs = [log for log in logs if log.timestamp >= cutoff_time]
        
        for log in recent_logs:
            # Count source IPs
            source_ips[log.source_ip] = source_ips.get(log.source_ip, 0) + 1
            
            # Count destination IPs
            if log.destination_ip:
                destination_ips[log.destination_ip] = destination_ips.get(log.destination_ip, 0) + 1
            
            # Count actions
            actions[log.action] = actions.get(log.action, 0) + 1
            
            # Count users
            if log.user:
                users[log.user] = users.get(log.user, 0) + 1
        
        # Calculate statistics
        baseline = {
            "source_ip_counts": source_ips,
            "destination_ip_counts": destination_ips,
            "action_counts": actions,
            "user_counts": users,
            "total_logs": len(recent_logs),
            "unique_source_ips": len(source_ips),
            "unique_actions": len(actions),
            "established_at": datetime.utcnow().isoformat(),
        }
        
        self.baseline_stats = baseline
        self.baseline_established = True
        
        logger.info(
            "Baseline established",
            total_logs=len(recent_logs),
            unique_ips=len(source_ips),
        )
        
        return baseline

    def detect_anomalies(
        self,
        logs: List[LogEntry],
        threshold: float = 2.0,
    ) -> List[Dict[str, Any]]:
        """Detect anomalies in logs using statistical methods.
        
        Args:
            logs: List of log entries to analyze
            threshold: Z-score threshold for anomaly detection (default: 2.0)
            
        Returns:
            List of anomaly dictionaries
        """
        if not self.baseline_established:
            logger.warning("Baseline not established, skipping anomaly detection")
            return []
        
        anomalies = []
        
        # Calculate current statistics
        source_ips = {}
        actions = {}
        failed_logins = {}
        
        for log in logs:
            source_ips[log.source_ip] = source_ips.get(log.source_ip, 0) + 1
            actions[log.action] = actions.get(log.action, 0) + 1
            
            # Track failed logins
            if log.action in ["login_attempt", "login_failed"] and log.status == "failure":
                failed_logins[log.source_ip] = failed_logins.get(log.source_ip, 0) + 1
        
        baseline_ips = self.baseline_stats.get("source_ip_counts", {})
        baseline_actions = self.baseline_stats.get("action_counts", {})
        baseline_total = self.baseline_stats.get("total_logs", 1)
        
        # Detect IP anomalies (unusual source IPs)
        for ip, count in source_ips.items():
            baseline_count = baseline_ips.get(ip, 0)
            baseline_avg = baseline_total / max(len(baseline_ips), 1)
            
            # Calculate z-score
            if baseline_avg > 0:
                z_score = (count - baseline_avg) / max(np.sqrt(baseline_avg), 1)
                if z_score > threshold:
                    anomalies.append({
                        "type": "unusual_source_ip",
                        "ip": ip,
                        "count": count,
                        "baseline_count": baseline_count,
                        "z_score": z_score,
                        "severity": "high" if z_score > 3.0 else "medium",
                    })
        
        # Detect failed login anomalies
        for ip, count in failed_logins.items():
            if count > 10:  # More than 10 failed logins
                anomalies.append({
                    "type": "brute_force",
                    "ip": ip,
                    "failed_attempts": count,
                    "severity": "critical" if count > 50 else "high",
                })
        
        # Detect unusual actions
        for action, count in actions.items():
            baseline_count = baseline_actions.get(action, 0)
            if baseline_count == 0 and count > 5:  # New action with multiple occurrences
                anomalies.append({
                    "type": "unusual_action",
                    "action": action,
                    "count": count,
                    "severity": "medium",
                })
        
        logger.info(f"Detected {len(anomalies)} anomalies")
        return anomalies

    def calculate_anomaly_score(self, log: LogEntry) -> float:
        """Calculate anomaly score for a single log entry.
        
        Args:
            log: Log entry to score
            
        Returns:
            Anomaly score (0.0-1.0)
        """
        if not self.baseline_established:
            return 0.0
        
        score = 0.0
        
        baseline_ips = self.baseline_stats.get("source_ip_counts", {})
        baseline_actions = self.baseline_stats.get("action_counts", {})
        
        # Check if source IP is unusual
        if log.source_ip not in baseline_ips:
            score += 0.3
        
        # Check if action is unusual
        if log.action not in baseline_actions:
            score += 0.2
        
        # Check for failed login
        if log.action in ["login_attempt", "login_failed"] and log.status == "failure":
            score += 0.3
        
        # Check for unusual destination
        if log.destination_ip and log.destination_ip.startswith(("185.", "192.")):
            score += 0.2
        
        return min(score, 1.0)


# Global instance
_anomaly_detector: Optional[AnomalyDetector] = None


def get_anomaly_detector() -> AnomalyDetector:
    """Get or create anomaly detector instance."""
    global _anomaly_detector
    if _anomaly_detector is None:
        _anomaly_detector = AnomalyDetector()
    return _anomaly_detector

