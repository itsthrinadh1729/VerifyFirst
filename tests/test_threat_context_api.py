import pytest
from backend.api.analyze import analyze_url
from backend.api.schemas import AnalyzeRequest
import asyncio

@pytest.mark.asyncio
async def test_analyze_url_returns_threat_context():
    request = AnalyzeRequest(url="http://google.com.evil.com")
    response = await analyze_url(request)
    
    assert response.status in ("SUSPICIOUS", "DANGEROUS")
    assert response.threat_context is not None
    assert response.threat_context.title
    assert response.threat_context.summary
    assert response.threat_context.technical_details
    assert response.threat_context.user_impact
    assert response.threat_context.recommended_action

@pytest.mark.asyncio
async def test_analyze_safe_url_returns_no_threat_context():
    request = AnalyzeRequest(url="https://www.google.com")
    response = await analyze_url(request)
    
    assert response.status == "SAFE"
    assert response.threat_context is None

