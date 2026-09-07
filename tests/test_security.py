import pytest
import pytest_asyncio
from httpx import AsyncClient
import httpx
from unittest.mock import patch

from backend.main import app
from backend.detection.intelligence.schemas import ThreatIntelResult

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        yield ac

# 14D & 14H — Backend Input Validation & URL parsing

@pytest.mark.asyncio
async def test_oversized_url(client):
    # Generating an oversized URL that exceeds typical max lengths (e.g. >2048 chars)
    # The API should reject it with 422
    long_url = "https://example.com/" + ("a" * 3000)
    response = await client.post("/api/v1/analyze", json={"url": long_url})
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_control_characters_in_url(client):
    url = "https://example.com/test\x00\x08"
    response = await client.post("/api/v1/analyze", json={"url": url})
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_malformed_url_string(client):
    url = "not-a-url"
    response = await client.post("/api/v1/analyze", json={"url": url})
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_invalid_scheme(client):
    url = "ftp://example.com"
    response = await client.post("/api/v1/analyze", json={"url": url})
    assert response.status_code == 422

# 14L — XSS Revalidation simulation
@pytest.mark.asyncio
async def test_malicious_xss_url_parsing(client):
    # Ensure that passing XSS vectors through the URL does not crash the heuristic parser
    url = 'https://example.com/?q=<script>alert(1)</script>'
    response = await client.post("/api/v1/analyze", json={"url": url})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")

from backend.detection.intelligence.providers import GoogleSafeBrowsingProvider

# 14G — Threat Intelligence Privacy Audit
@pytest.mark.asyncio
async def test_privacy_stripping(client):
    # We want to ensure that if a user passes a URL with query strings and paths,
    # the provider only sends the host to the external API.
    provider = GoogleSafeBrowsingProvider(api_key="test")
    url = "https://example.com/reset-password?token=secret#top"
    
    # Test the internal privacy stripping function directly
    safe_url = provider._get_privacy_preserving_domain_url(url)
    
    # Confirm credentials/path/query are stripped!
    assert safe_url == "https://example.com/"
    assert "token" not in safe_url
    assert "secret" not in safe_url
    assert "reset-password" not in safe_url

    # Check payload generation structure
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response = httpx.Response(200, json={"matches": []})
        mock_post.return_value = mock_response
        
        await provider.check_url(url)
        assert mock_post.called
        args, kwargs = mock_post.call_args
        payload = kwargs.get("json")
        entries = payload["threatInfo"]["threatEntries"]
        assert entries[0]["url"] == "https://example.com/"

# 14E — SSRF Internal URL behavior
@pytest.mark.asyncio
async def test_internal_url_ssrf_behavior(client):
    # Verify that local URLs are processed normally (or trigger IP rules)
    # but do NOT alter the network destination of the Safe Browsing request
    
    url = "http://127.0.0.1/admin"
    response = await client.post("/api/v1/analyze", json={"url": url})
    assert response.status_code == 200
    
    # Should trigger IP_ADDRESS_HOST heuristic
    data = response.json()
    reasons = [r["rule"] for r in data["reasons"]]
    assert "IP_ADDRESS_HOST" in reasons
    
    # Safe Browsing API is still called with the internal IP, but the request 
    # itself goes to safebrowsing.googleapis.com, so it's not SSRF.
    provider = GoogleSafeBrowsingProvider(api_key="test")
    with patch("httpx.AsyncClient.post") as mock_post:
        mock_response = httpx.Response(200, json={"matches": []})
        mock_post.return_value = mock_response
        
        await provider.check_url(url)
        assert mock_post.called
        args, kwargs = mock_post.call_args
        # Assertion: The request destination is Google, NOT the user's IP.
        assert args[0].startswith("https://safebrowsing.googleapis.com")
        
        payload = kwargs.get("json")
        submitted_url = payload["threatInfo"]["threatEntries"][0]["url"]
        assert submitted_url == "http://127.0.0.1/"
