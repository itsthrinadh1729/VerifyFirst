"""Regression tests for WhatsApp URL extraction timestamp contamination bug.

Verifies that URLs sent to the backend are not contaminated by WhatsApp
timestamps (e.g. "10:25") being concatenated to the URL string.

These tests exercise the backend /api/v1/analyze endpoint with the exact
URL patterns that the extension's content script extracts, ensuring that:
1. Clean URLs are correctly analyzed
2. Legitimate URLs with ports, paths, queries, fragments are preserved
3. Timestamp-corrupted URLs (like "https://www.google.com10:25/") are
   recognizably different from their clean counterparts

The content-script-side fix is in whatsappScanner.ts; these tests guard
against the corruption reaching the backend.
"""

import pytest
import httpx
from backend.main import app


# ─── Clean URLs that MUST be accepted and analyzed correctly ────────────────

@pytest.mark.asyncio
async def test_clean_google_url():
    """https://www.google.com must be accepted and analyzed as SAFE."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "https://www.google.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SAFE"


@pytest.mark.asyncio
async def test_clean_example_url():
    """https://example.com must be accepted and analyzed as SAFE."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "https://example.com"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SAFE"


@pytest.mark.asyncio
async def test_clean_url_with_path():
    """https://example.com/path must be accepted."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "https://example.com/path"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SAFE"


@pytest.mark.asyncio
async def test_clean_url_with_query_params():
    """https://example.com/path?id=123 must be accepted."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "https://example.com/path?id=123"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SAFE"


@pytest.mark.asyncio
async def test_clean_url_with_port_8080():
    """https://example.com:8080 must be accepted — legitimate port."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "https://example.com:8080"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SAFE"


@pytest.mark.asyncio
async def test_clean_url_with_port_and_path():
    """https://example.com:8080/path must be accepted — legitimate port + path."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "https://example.com:8080/path"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SAFE"


# ─── Timestamp-contaminated URLs — the exact regression case ───────────────

@pytest.mark.asyncio
async def test_timestamp_contaminated_url_is_different_from_clean():
    """The corrupted URL https://www.google.com10:25/ must NOT be treated as
    equivalent to https://www.google.com. This is the exact regression case.

    The URL https://www.google.com10:25/ has hostname 'www.google.com10'
    and port 25 — it is structurally different from the intended URL.
    The backend should either reject it or analyze it differently.
    """
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        # The clean URL
        clean_resp = await client.post("/api/v1/analyze", json={"url": "https://www.google.com"})
        assert clean_resp.status_code == 200
        clean_data = clean_resp.json()

        # The contaminated URL (what the bug produced)
        dirty_resp = await client.post("/api/v1/analyze", json={"url": "https://www.google.com10:25/"})
        assert dirty_resp.status_code == 200
        dirty_data = dirty_resp.json()

        # The contaminated URL must NOT be analyzed as the clean one
        # It should have a different status proving it was not normalized to the clean form
        assert dirty_data["status"] != clean_data["status"], \
            "Contaminated URL must not be silently normalized to the clean URL by the backend"


@pytest.mark.asyncio
async def test_contaminated_url_not_safe():
    """The corrupted URL https://www.google.com10:25/ should NOT be marked SAFE,
    since 'www.google.com10' is not a real domain."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "https://www.google.com10:25/"})
        assert response.status_code == 200
        data = response.json()
        # A URL with hostname 'www.google.com10' on port 25 is suspicious
        # The exact status depends on detection rules, but it should NOT be SAFE
        assert data["status"] != "SAFE", \
            "Timestamp-contaminated URL with fake hostname must not be SAFE"


# ─── URL normalization consistency ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_normalized_url_returns_consistent_status():
    """The backend must consistently return valid results for valid URLs."""
    urls_to_test = [
        "https://www.google.com",
        "https://example.com",
        "https://example.com/path",
        "https://example.com/path?id=123",
        "https://example.com:8080",
        "https://example.com:8080/path",
    ]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        for url in urls_to_test:
            response = await client.post("/api/v1/analyze", json={"url": url})
            assert response.status_code == 200
            data = response.json()
            assert "status" in data, f"Response must include 'status' field for {url}"


# ─── Legitimate URLs with numeric components must NOT be corrupted ─────────

@pytest.mark.asyncio
async def test_url_with_port_443():
    """Port 443 (HTTPS default) must be preserved, not stripped as a timestamp."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "https://example.com:443/secure"})
        assert response.status_code == 200


@pytest.mark.asyncio
async def test_url_with_port_3000():
    """Port 3000 (dev server) must be preserved."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.post("/api/v1/analyze", json={"url": "http://example.com:3000/api/v1"})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "SAFE"


@pytest.mark.asyncio
async def test_url_with_numeric_path_components():
    """Numeric path and query components must not be mistaken for timestamps."""
    test_urls = [
        "https://example.com/article/12345",
        "https://example.com/page?id=42&sort=desc",
        "https://example.com/2024/01/15/news",
        "https://example.com/api/v2/users/100",
    ]
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        for url in test_urls:
            response = await client.post("/api/v1/analyze", json={"url": url})
            assert response.status_code == 200, f"Numeric-path URL rejected: {url}"
            data = response.json()
            assert data["status"] == "SAFE", f"Numeric-path URL not SAFE: {url}"
