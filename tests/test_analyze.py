"""Phase 1A — POST /api/v1/analyze API endpoint and input validation tests."""

import pytest
import httpx
from backend.main import app


@pytest.mark.asyncio
async def test_valid_https_url():
    """Verify standard HTTPS URL is accepted and returns 200 with baseline response."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "https://example.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("SAFE", "SUSPICIOUS", "DANGEROUS", "ANALYSIS_UNAVAILABLE")
        assert 0 <= data["risk_score"] <= 100
        assert isinstance(data["reasons"], list)
        assert "confidence" not in data


@pytest.mark.asyncio
async def test_valid_http_url():
    """Verify standard HTTP URL is accepted."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "http://example.org/path"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SAFE"


@pytest.mark.asyncio
async def test_empty_url():
    """Verify empty string or whitespace URL is rejected with 422."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": ""})
        assert response.status_code == 422

        response_ws = await client.post("/api/v1/analyze", json={"url": "   "})
        assert response_ws.status_code == 422


@pytest.mark.asyncio
async def test_missing_url_field():
    """Verify request with missing URL field is rejected with 422."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={})
        assert response.status_code == 422

        response_null = await client.post("/api/v1/analyze", json={"url": None})
        assert response_null.status_code == 422


@pytest.mark.asyncio
async def test_malformed_url():
    """Verify malformed URLs without hostname or invalid format are rejected with 422."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        # Missing hostname
        response1 = await client.post("/api/v1/analyze", json={"url": "https://"})
        assert response1.status_code == 422
        
        response1b = await client.post("/api/v1/analyze", json={"url": "http://"})
        assert response1b.status_code == 422

        # Missing scheme & invalid format
        response2 = await client.post("/api/v1/analyze", json={"url": "not-a-url"})
        assert response2.status_code == 422

        # Invalid scheme structure
        response3 = await client.post("/api/v1/analyze", json={"url": "://bad-url"})
        assert response3.status_code == 422


@pytest.mark.asyncio
async def test_unsupported_schemes():
    """Verify non-HTTP/HTTPS schemes (ftp, javascript, file, data) are rejected with 422."""
    unsupported = [
        "ftp://ftp.example.com/file.txt",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,<script>alert(1)</script>",
        "ws://example.com/socket",
        "ssh://git@github.com",
    ]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        for url in unsupported:
            response = await client.post("/api/v1/analyze", json={"url": url})
            assert response.status_code == 422, f"Expected 422 for scheme in {url}"


@pytest.mark.asyncio
async def test_url_exceeding_max_length():
    """Verify URLs longer than 2048 characters are rejected with 422."""
    long_url = "https://example.com/" + "a" * 2050
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": long_url})
        assert response.status_code == 422


@pytest.mark.asyncio
async def test_url_containing_control_characters():
    """Verify URLs containing control characters or null bytes are rejected with 422."""
    control_char_urls = [
        "https://example.com/\x00evil",
        "https://example.com/\r\nSet-Cookie:admin=1",
        "https://example.com/test\x1b[31m",
        "https://example\x7f.com",
    ]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        for url in control_char_urls:
            response = await client.post("/api/v1/analyze", json={"url": url})
            assert response.status_code == 422, f"Expected 422 for control character in {repr(url)}"


@pytest.mark.asyncio
async def test_url_with_normal_query_parameters():
    """Verify complex but valid query parameters and fragments are accepted."""
    url = "https://example.com/search?q=cybersecurity+tools&page=2&filter=active#results"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": url})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SAFE"


@pytest.mark.asyncio
async def test_suspicious_looking_payload_parsed_as_string_without_execution():
    """Verify URLs with command injection or SQL injection payloads are safely parsed as strings."""
    suspicious_urls = [
        "https://example.com/page?id=1;DROP%20TABLE%20users;--",
        "https://example.com/exec?cmd=rm%20-rf%20/&param=test",
        "https://example.com/login?redirect=http://internal-host:8080/admin",
        "http://192.168.1.1/admin/setup",
    ]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        for url in suspicious_urls:
            response = await client.post("/api/v1/analyze", json={"url": url})
            assert response.status_code == 200
            data = response.json()
            assert "status" in data


@pytest.mark.asyncio
async def test_analyze_integration_returns_structured_reasons():
    """Verify POST /api/v1/analyze returns structured reasons with rule and message fields."""
    url = "http://192.168.1.1/admin"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": url})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SUSPICIOUS"
        assert data["risk_score"] == 40
        assert len(data["reasons"]) == 1
        assert data["reasons"][0]["rule"] == "IP_ADDRESS_HOST"
        assert "IP address" in data["reasons"][0]["message"]

