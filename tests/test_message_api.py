import pytest
import pytest_asyncio
import httpx
from httpx import AsyncClient

from backend.main import app

@pytest_asyncio.fixture
async def client():
    async with AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as ac:
        yield ac


@pytest.mark.asyncio
async def test_analyze_message_safe(client):
    response = await client.post(
        "/api/v1/analyze-message",
        json={"message": "Hey, what time are we meeting tomorrow?"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SAFE"
    assert data["risk_score"] == 0
    assert data["asset_type"] == "message"
    assert data["reasons"] == []


@pytest.mark.asyncio
async def test_analyze_message_suspicious(client):
    response = await client.post(
        "/api/v1/analyze-message",
        json={"message": "Please enter your password."}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUSPICIOUS"
    assert data["risk_score"] == 30
    assert data["asset_type"] == "message"
    rule_ids = [r["rule"] for r in data["reasons"]]
    assert "CREDENTIAL_REQUEST" in rule_ids


@pytest.mark.asyncio
async def test_analyze_message_dangerous(client):
    response = await client.post(
        "/api/v1/analyze-message",
        json={"message": "Your account will be suspended. Verify your password immediately."}
    )
    assert response.status_code == 200
    data = response.json()
    print("DEBUG:", data)
    assert data["status"] == "DANGEROUS"
    # Threat(25) + Credential(30) + Urgency(10) + SE(15) = 80
    assert data["risk_score"] == 80
    assert data["asset_type"] == "message"
    rule_ids = [r["rule"] for r in data["reasons"]]
    assert "ACCOUNT_THREAT" in rule_ids
    assert "CREDENTIAL_REQUEST" in rule_ids
    assert "URGENCY_LANGUAGE" in rule_ids
    assert "SOCIAL_ENGINEERING_PATTERN" in rule_ids
