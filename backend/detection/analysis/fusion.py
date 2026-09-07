"""Evidence Fusion Layer: Combines heuristic results with threat intelligence."""

from backend.detection.engine.scorer import DetectionResult, DetectionReason
from backend.detection.intelligence.schemas import ThreatIntelResult

def fuse_evidence(heuristic_result: DetectionResult, intel_result: ThreatIntelResult) -> DetectionResult:
    """
    Combines the deterministic heuristic score with the external reputation result.
    
    Policy:
    - If GSB MATCH -> risk_score = 100, status = DANGEROUS, append reason.
    - If GSB NO MATCH -> use heuristic result untouched.
    - If GSB UNAVAILABLE -> use heuristic result untouched.
    """
    
    # If the provider is unavailable or reports no match, fallback to heuristics entirely
    if not intel_result.available or not intel_result.is_malicious:
        return heuristic_result
        
    # If there is a confirmed match, override the status and clamp score to 100
    fused_reasons = list(heuristic_result.reasons)
    fused_reasons.append(
        DetectionReason(
            rule="THREAT_INTELLIGENCE_MATCH",
            message=intel_result.reason or "The URL has been identified by a trusted threat-intelligence source."
        )
    )
    
    return DetectionResult(
        status="DANGEROUS",
        risk_score=100,
        reasons=fused_reasons
    )
