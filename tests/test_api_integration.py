import pytest
import pytest_asyncio
import httpx
from httpx import AsyncClient
from unittest.mock import patch, MagicMock

from backend.main import app
from backend.detection.intelligence.schemas import ThreatIntelResult

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

# 13A - Test API Integration with heuristics
@pytest.mark.asyncio
async def test_api_safe_url(client):
    response = await client.post("/api/v1/analyze", json={"url": "https://google.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SAFE"
    assert data["risk_score"] == 0
    assert len(data["reasons"]) == 0

@pytest.mark.asyncio
async def test_api_typosquatting(client):
    response = await client.post("/api/v1/analyze", json={"url": "http://paypa1-login.example.com/verify"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUSPICIOUS"
    # Typo (30) + Suspicious Encoding (0) = 30
    # Actually wait, maybe 30 points.
    assert data["risk_score"] >= 30
    reasons = [r["rule"] for r in data["reasons"]]
    assert "TYPOSQUATTING" in reasons

@pytest.mark.asyncio
async def test_api_brand_impersonation(client):
    response = await client.post("/api/v1/analyze", json={"url": "http://apple-id-check.example.com/signin"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUSPICIOUS"
    assert data["risk_score"] >= 35
    reasons = [r["rule"] for r in data["reasons"]]
    assert "BRAND_IMPERSONATION" in reasons

@pytest.mark.asyncio
async def test_api_multi_rule(client):
    url = "http://192.168.1.1:8080/path/to/something/very/long/that/triggers/excessive/length@example.com/test?q=" + ("a" * 150)
    response = await client.post("/api/v1/analyze", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "DANGEROUS"
    assert data["risk_score"] >= 75
    reasons = [r["rule"] for r in data["reasons"]]
    assert "IP_ADDRESS_HOST" in reasons
    assert "USERINFO_AT_SYMBOL" in reasons
    assert "EXCESSIVE_URL_LENGTH" in reasons

# 13B & 13C - Threat Intelligence Integration and Failure
@pytest.mark.asyncio
@patch("backend.detection.intelligence.service.ThreatIntelService.check_url")
async def test_api_threat_intel_match(mock_check_url, client):
    mock_check_url.return_value = ThreatIntelResult(
        available=True, is_malicious=True, confidence="high", source="GSB", reason="Match"
    )
    
    response = await client.post("/api/v1/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "DANGEROUS"
    assert data["risk_score"] == 100
    reasons = [r["rule"] for r in data["reasons"]]
    assert "THREAT_INTELLIGENCE_MATCH" in reasons

@pytest.mark.asyncio
@patch("backend.detection.intelligence.service.ThreatIntelService.check_url")
async def test_api_threat_intel_no_match(mock_check_url, client):
    mock_check_url.return_value = ThreatIntelResult(
        available=True, is_malicious=False, confidence="high", source="GSB", reason=None
    )
    
    # Use a typo URL to see heuristics preserved
    response = await client.post("/api/v1/analyze", json={"url": "http://paypa1-login.example.com/"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUSPICIOUS"
    reasons = [r["rule"] for r in data["reasons"]]
    assert "TYPOSQUATTING" in reasons
    assert "THREAT_INTELLIGENCE_MATCH" not in reasons

@pytest.mark.asyncio
@patch("backend.detection.intelligence.service.ThreatIntelService.check_url")
async def test_api_threat_intel_unavailable(mock_check_url, client):
    mock_check_url.return_value = ThreatIntelResult.unavailable()
    
    # Use a typo URL to see heuristics preserved
    response = await client.post("/api/v1/analyze", json={"url": "http://paypa1-login.example.com/"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUSPICIOUS"
    reasons = [r["rule"] for r in data["reasons"]]
    assert "TYPOSQUATTING" in reasons
    assert "THREAT_INTELLIGENCE_MATCH" not in reasons

@pytest.mark.asyncio
@patch("backend.detection.intelligence.service.ThreatIntelService.check_url")
async def test_api_threat_intel_exception_resilience(mock_check_url, client):
    # Simulate an unhandled exception bursting out of the provider
    mock_check_url.side_effect = Exception("Critical network failure")
    
    # We should handle it at the API layer or the provider layer.
    # Currently the FastAPI endpoint might 500 if the service itself raises.
    # Let's ensure the endpoint itself is resilient if we wrap it, or just rely on the global exception handler.
    # Actually, if we mock check_url to raise, it will raise in analyze.py. 
    # Let's see if analyze.py handles it gracefully. If not, it will return 500.
    
    response = await client.post("/api/v1/analyze", json={"url": "https://google.com/"})
    
    # In a fully robust API, an external service failure shouldn't crash the core heuristic flow.
    # So we should expect 200 with heuristic results (SAFE).
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SAFE"
