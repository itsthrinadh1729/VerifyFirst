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
async def test_adversarial_ordinary_security_words(client):
    """Category A - Ordinary messages containing security words"""
    messages = [
        "I forgot my password.",
        "Can you send me the payment receipt?",
        "The OTP system was down yesterday.",
        "Please verify the assignment.",
        "My account password expires next month."
    ]
    for msg in messages:
        response = await client.post("/api/v1/analyze-message", json={"message": msg})
        data = response.json()
        assert data["status"] in ("SAFE", "SUSPICIOUS")
        if data["status"] == "SUSPICIOUS":
            # Just ensure it doesn't cross into DANGEROUS easily without strong combinations
            assert data["risk_score"] < 66

@pytest.mark.asyncio
async def test_adversarial_urgency_alone(client):
    """Category B - Urgency alone"""
    messages = [
        "Please reply urgently.",
        "Call me immediately.",
        "This is urgent."
    ]
    for msg in messages:
        response = await client.post("/api/v1/analyze-message", json={"message": msg})
        data = response.json()
        reasons = [r["rule"] for r in data["reasons"]]
        if "URGENCY_OR_TIME_PRESSURE" in reasons:
            assert data["risk_score"] < 66
            assert data["status"] in ("SAFE", "SUSPICIOUS")

@pytest.mark.asyncio
async def test_adversarial_credential_request(client):
    """Category C - Credential request"""
    msg = "Please enter your password to continue."
    response = await client.post("/api/v1/analyze-message", json={"message": msg})
    data = response.json()
    reasons = [r["rule"] for r in data["reasons"]]
    assert "CREDENTIAL_REQUEST" in reasons

@pytest.mark.asyncio
async def test_adversarial_otp_request(client):
    """Category D - OTP request"""
    msg = "Send me the OTP you received."
    response = await client.post("/api/v1/analyze-message", json={"message": msg})
    data = response.json()
    reasons = [r["rule"] for r in data["reasons"]]
    assert "OTP_OR_PIN_REQUEST" in reasons

@pytest.mark.asyncio
async def test_adversarial_account_threat(client):
    """Category E - Account threat"""
    msg = "Your account will be suspended."
    response = await client.post("/api/v1/analyze-message", json={"message": msg})
    data = response.json()
    reasons = [r["rule"] for r in data["reasons"]]
    assert "ACCOUNT_THREAT" in reasons

@pytest.mark.asyncio
async def test_adversarial_combined_social_engineering(client):
    """Category F - Combined social engineering"""
    msg1 = "Your account will be suspended immediately. Verify your password now."
    response = await client.post("/api/v1/analyze-message", json={"message": msg1})
    data = response.json()
    assert data["status"] == "DANGEROUS"

    msg2 = "This is support. Your account has a security problem. Send the OTP immediately."
    response = await client.post("/api/v1/analyze-message", json={"message": msg2})
    data = response.json()
    assert data["status"] == "DANGEROUS"

@pytest.mark.asyncio
async def test_adversarial_explicit_secrecy(client):
    """Category G - Explicit secrecy/manipulation"""
    messages = [
        "Do not tell anyone about this.",
        "Keep this secret.",
        "Don't contact anyone else."
    ]
    for msg in messages:
        response = await client.post("/api/v1/analyze-message", json={"message": msg})
        data = response.json()
        reasons = [r["rule"] for r in data["reasons"]]
        assert "SOCIAL_ENGINEERING_PATTERN" in reasons

@pytest.mark.asyncio
async def test_adversarial_prize_reward(client):
    """Category H - Prize/reward boundary"""
    benign = [
        "Congratulations on your achievement!",
        "You won the competition."
    ]
    for msg in benign:
        response = await client.post("/api/v1/analyze-message", json={"message": msg})
        data = response.json()
        # Should be SAFE or low score SUSPICIOUS
        assert data["risk_score"] < 50

    malicious = "Claim your reward now by providing your account details."
    response = await client.post("/api/v1/analyze-message", json={"message": malicious})
    data = response.json()
    assert data["risk_score"] > 25

@pytest.mark.asyncio
async def test_adversarial_unicode_and_normalization(client):
    """4C.5 Unicode and normalization testing"""
    messages = [
        "VERIFY   YOUR   PASSWORD",
        "verify your password",
        "vErIfY\tyOuR\nPaSsWoRd"
    ]
    results = []
    for msg in messages:
        response = await client.post("/api/v1/analyze-message", json={"message": msg})
        results.append(response.json())
    
    # Should all be parsed deterministically and trigger same rules
    assert results[0]["risk_score"] == results[1]["risk_score"]
    assert results[1]["risk_score"] == results[2]["risk_score"]

@pytest.mark.asyncio
async def test_adversarial_length_boundaries(client):
    messages = [
        "a" * 3999,
        "a" * 4000,
        "a" * 4001,
    ]
    for msg in messages:
        response = await client.post("/api/v1/analyze-message", json={"message": msg})
        data = response.json()
        assert data["status"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")

@pytest.mark.asyncio
async def test_score_boundaries_message(client):
    """4C.8 Score integrity"""
    response = await client.post("/api/v1/analyze-message", json={"message": "hello"})
    data = response.json()
    assert 0 <= data["risk_score"] <= 100
    if data["status"] == "SAFE":
        assert data["risk_score"] <= 25

    response = await client.post("/api/v1/analyze-message", json={"message": "Send your OTP immediately."})
    data = response.json()
    if data["status"] == "SUSPICIOUS":
        assert 26 <= data["risk_score"] <= 65
    elif data["status"] == "DANGEROUS":
        assert 66 <= data["risk_score"] <= 100

@pytest.mark.asyncio
async def test_reason_integrity_message(client):
    response = await client.post("/api/v1/analyze-message", json={"message": "Send your OTP immediately."})
    data = response.json()
    reasons = [r["rule"] for r in data["reasons"]]
    assert "EXTENSION_MISMATCH_DECEPTION" not in reasons
    assert data["asset_type"] == "message"
