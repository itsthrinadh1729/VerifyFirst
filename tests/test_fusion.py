"""Tests for Evidence Fusion Layer."""

import pytest
from backend.detection.engine.scorer import DetectionResult, DetectionReason
from backend.detection.intelligence.schemas import ThreatIntelResult
from backend.detection.analysis.fusion import fuse_evidence

def test_fuse_evidence_with_threat_match():
    """Verify that a threat intelligence match forces DANGEROUS status and 100 risk score."""
    heuristic_result = DetectionResult(
        status="SAFE",
        risk_score=0,
        reasons=[]
    )
    
    intel_result = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="Google Safe Browsing",
        reason="Test malicious domain"
    )
    
    fused = fuse_evidence(heuristic_result, intel_result)
    
    assert fused.status == "DANGEROUS"
    assert fused.risk_score == 100
    assert len(fused.reasons) == 1
    assert fused.reasons[0].rule == "THREAT_INTELLIGENCE_MATCH"
    assert fused.reasons[0].message == "Test malicious domain"

def test_fuse_evidence_with_no_threat_match():
    """Verify that no match keeps the heuristic score untouched."""
    heuristic_result = DetectionResult(
        status="SUSPICIOUS",
        risk_score=40,
        reasons=[DetectionReason(rule="TEST_RULE", message="Test message")]
    )
    
    intel_result = ThreatIntelResult(
        available=True,
        is_malicious=False,
        confidence="high",
        source="Google Safe Browsing",
        reason=None
    )
    
    fused = fuse_evidence(heuristic_result, intel_result)
    
    assert fused.status == "SUSPICIOUS"
    assert fused.risk_score == 40
    assert len(fused.reasons) == 1
    assert fused.reasons[0].rule == "TEST_RULE"

def test_fuse_evidence_when_intel_unavailable():
    """Verify that unavailable threat intel keeps the heuristic score untouched."""
    heuristic_result = DetectionResult(
        status="SAFE",
        risk_score=10,
        reasons=[DetectionReason(rule="TEST_RULE", message="Test message")]
    )
    
    intel_result = ThreatIntelResult.unavailable()
    
    fused = fuse_evidence(heuristic_result, intel_result)
    
    assert fused.status == "SAFE"
    assert fused.risk_score == 10
    assert len(fused.reasons) == 1
