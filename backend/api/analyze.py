from fastapi import APIRouter
from backend.api.schemas import AnalyzeRequest, AnalyzeResponse, DetectionReasonItem
from backend.detection.engine.scorer import analyze_url_security
from backend.detection.intelligence.service import ThreatIntelService
from backend.detection.analysis.fusion import fuse_evidence
from backend.detection.analysis.analyzer import analyze_threats
from backend.detection.analysis.severity import assess_threat
from backend.detection.analysis.context import build_threat_context

router = APIRouter(tags=["Analysis"])
intel_service = ThreatIntelService()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_url(request: AnalyzeRequest) -> AnalyzeResponse:
    """
    Analyze a submitted website URL for potential security risks using heuristics and threat intelligence.
    
    SECURITY NOTE (14I): 
    This endpoint currently lacks rate limiting, concurrent connection limits, and IP-based throttling 
    because VerifyFirst is designed as a local individual deployment. 
    If deployed publicly, an API gateway or middleware (like slowapi) MUST be added to prevent resource exhaustion and abuse.
    """
    # 1. Deterministic URL heuristics
    heuristic_result = analyze_url_security(request.url)

    # 2. External threat intelligence
    try:
        intel_result = await intel_service.check_url(request.url)
    except Exception as e:
        # Failsafe if the service/provider abstraction leaks an exception
        from backend.detection.intelligence.schemas import ThreatIntelResult
        import logging
        logging.getLogger(__name__).error(f"Unhandled exception in ThreatIntelService: {e}")
        intel_result = ThreatIntelResult.unavailable()

    # 3. Evidence Fusion
    final_result = fuse_evidence(heuristic_result, intel_result)

    # 4. Threat Explanation (Module 4D)
    analysis = analyze_threats(final_result)
    assessment = assess_threat(analysis)
    context = build_threat_context(analysis, assessment)
    
    threat_context_resp = None
    if context:
        threat_context_resp = {
            "title": context.title,
            "summary": context.summary,
            "technical_details": list(context.technical_details),
            "user_impact": context.user_impact,
            "recommended_action": context.recommended_action,
        }

    return AnalyzeResponse(
        status=final_result.status,
        risk_score=final_result.risk_score,
        reasons=[
            DetectionReasonItem(rule=r.rule, message=r.message)
            for r in final_result.reasons
        ],
        threat_context=threat_context_resp,
    )

