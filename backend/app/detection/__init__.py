"""Detection module for ATT&CK-native detection rules."""

from app.detection.attack_rules import ATTACK_DETECTION_RULES, evaluate_attack_rules

__all__ = ["ATTACK_DETECTION_RULES", "evaluate_attack_rules"]

