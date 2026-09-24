"""Evidence Fusion Layer: Combines heuristic results with threat intelligence."""

from backend.detection.engine.scorer import DetectionResult, DetectionReason
from backend.detection.intelligence.schemas import ThreatIntelResult, FusionEvidence

def build_intelligence_evidence(
    intel_result,
) -> FusionEvidence | None:
    if not intel_result.available:
        return None

    if not intel_result.is_malicious:
        return None

    return FusionEvidence(
        source=intel_result.source or "unknown",
        rule_id="THREAT_INTELLIGENCE_MATCH",
        message=(
            intel_result.reason
            or "The URL has been identified by a threat-intelligence source."
        ),
        confidence=intel_result.confidence,
    )

def _has_intelligence_match(reasons):
    return any(
        reason.rule == "THREAT_INTELLIGENCE_MATCH"
        for reason in reasons
    )

def fuse_evidence(
    heuristic_result: DetectionResult,
    intel_result: ThreatIntelResult,
) -> DetectionResult:
    """
    Combines the deterministic heuristic score with the external reputation result.
    """
    intelligence_evidence = build_intelligence_evidence(intel_result)

    if intelligence_evidence is None:
        return heuristic_result

    fused_reasons = list(heuristic_result.reasons)

    if _has_intelligence_match(fused_reasons):
        return DetectionResult(
            status="DANGEROUS",
            risk_score=100,
            reasons=fused_reasons,
        )

    fused_reasons.append(
        DetectionReason(
            rule=intelligence_evidence.rule_id,
            message=intelligence_evidence.message,
        )
    )

    return DetectionResult(
        status="DANGEROUS",
        risk_score=100,
        reasons=fused_reasons,
    )
