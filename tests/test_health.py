"""Phase 0 — Health endpoint tests."""

import pytest
import httpx
from backend.main import app


@pytest.mark.asyncio
async def test_health_returns_ok():
    """Verify the health endpoint returns a 200 with status ok."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["phase"] == "1A"


@pytest.mark.asyncio
async def test_health_response_structure():
    """Verify the health response contains only expected fields."""
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
        response = await client.get("/health")
        data = response.json()
        assert set(data.keys()) == {"status", "phase"}
