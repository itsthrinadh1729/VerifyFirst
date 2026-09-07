from fastapi import APIRouter
from backend.api.schemas import AnalyzeRequest, AnalyzeResponse, DetectionReasonItem
from backend.detection.engine.scorer import analyze_url_security
from backend.detection.intelligence.service import ThreatIntelService
from backend.detection.analysis.fusion import fuse_evidence

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

    return AnalyzeResponse(
        status=final_result.status,
        risk_score=final_result.risk_score,
        reasons=[
            DetectionReasonItem(rule=r.rule, message=r.message)
            for r in final_result.reasons
        ],
    )

