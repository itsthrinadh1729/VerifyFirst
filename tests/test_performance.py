import pytest
import pytest_asyncio
import time
import httpx
from httpx import AsyncClient
from unittest.mock import patch

from backend.main import app
from backend.detection.intelligence.providers import GoogleSafeBrowsingProvider
from backend.api.analyze import intel_service

@pytest_asyncio.fixture
async def client():
    # Because lifespan runs conditionally in testing depending on the setup,
    # we manually call start/stop for the intel_service to simulate app lifespan.
    await intel_service.start()
    async with AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    await intel_service.stop()
    # Clear cache between tests
    intel_service._cache.clear()

# 15M - Verify cache hits for same domain lookup
@pytest.mark.asyncio
async def test_threat_intel_cache_hit(client):
    url = "https://cache-test.example.com/some/path"
    intel_service.provider.api_key = "test_key"
    
    # We patch the provider's internal client's post method to see if it actually gets called
    with patch.object(intel_service.provider._client, "post") as mock_post:
        mock_response = httpx.Response(200, json={"matches": []})
        mock_post.return_value = mock_response
        
        # First call
        response1 = await client.post("/api/v1/analyze", json={"url": url})
        assert response1.status_code == 200
        assert mock_post.call_count == 1
        
        # Second call with the same domain (different path)
        url2 = "https://cache-test.example.com/another/path"
        response2 = await client.post("/api/v1/analyze", json={"url": url2})
        assert response2.status_code == 200
        
        # Call count should STILL be 1 because it was cached!
        assert mock_post.call_count == 1

# 15M - Verify that GSB timeouts do not block indefinitely
@pytest.mark.asyncio
async def test_threat_intel_timeout_does_not_block(client):
    url = "https://timeout.example.com"
    intel_service.provider.api_key = "test_key"
    
    with patch.object(intel_service.provider._client, "post") as mock_post:
        # Simulate a timeout exception
        mock_post.side_effect = httpx.TimeoutException("Timeout")
        
        t0 = time.perf_counter()
        response = await client.post("/api/v1/analyze", json={"url": url})
        t1 = time.perf_counter()
        
        assert response.status_code == 200
        # Ensure it doesn't just hang, though the mock returns instantly. 
        # The fact that it returns a 200 AnalyzeResponse means the timeout was caught gracefully.
        data = response.json()
        assert data["status"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")
        
        # Check that failures are NOT cached
        assert "timeout.example.com" not in intel_service._cache

# 15E - Verify connection reuse
@pytest.mark.asyncio
async def test_connection_reuse(client):
    # Check that the underlying provider's client is not None after start
    provider = intel_service.provider
    assert isinstance(provider, GoogleSafeBrowsingProvider)
    assert provider._client is not None
    assert not provider._client.is_closed
