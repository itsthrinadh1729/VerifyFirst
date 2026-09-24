import pytest
from backend.detection.engine.scorer import DetectionResult
from backend.detection.protection.schemas import ProtectionAction
from backend.detection.protection.policy import evaluate_protection_policy

def test_safe_result_is_allowed():
    result = DetectionResult(status="SAFE", risk_score=0)
    decision = evaluate_protection_policy(result)
    assert decision.action == ProtectionAction.ALLOW

def test_suspicious_result_is_warned():
    result = DetectionResult(status="SUSPICIOUS", risk_score=50)
    decision = evaluate_protection_policy(result)
    assert decision.action == ProtectionAction.WARN

def test_dangerous_result_is_blocked():
    result = DetectionResult(status="DANGEROUS", risk_score=100)
    decision = evaluate_protection_policy(result)
    assert decision.action == ProtectionAction.BLOCK

def test_unknown_status_fails_safe_to_block():
    result = DetectionResult(status="UNKNOWN", risk_score=-1)
    decision = evaluate_protection_policy(result)
    assert decision.action == ProtectionAction.BLOCK
