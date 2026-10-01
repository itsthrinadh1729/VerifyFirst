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
async def test_cross_asset_no_contamination(client):
    """4C.6 Cross-asset adversarial test & 4C.7 Reason integrity"""
    url = "https://trusted.example@evil.example/"
    filename = "invoice.pdf.exe"
    msg = "Your account will be suspended. Send your OTP immediately."

    # Fire concurrently (even though we're in pytest-asyncio, gather works)
    import asyncio
    r_url, r_file, r_msg = await asyncio.gather(
        client.post("/api/v1/analyze", json={"url": url}),
        client.post("/api/v1/analyze-file", json={"filename": filename}),
        client.post("/api/v1/analyze-message", json={"message": msg})
    )

    data_url = r_url.json()
    data_file = r_file.json()
    data_msg = r_msg.json()

    # URL Checks
    url_reasons = [r["rule"] for r in data_url["reasons"]]
    assert "USERINFO_AT_SYMBOL" in url_reasons
    assert "EXTENSION_MISMATCH_DECEPTION" not in url_reasons
    assert "ACCOUNT_THREAT" not in url_reasons

    # File Checks
    assert data_file["asset_type"] == "file"
    file_reasons = [r["rule"] for r in data_file["reasons"]]
    assert "EXTENSION_MISMATCH_DECEPTION" in file_reasons
    assert "USERINFO_AT_SYMBOL" not in file_reasons
    assert "ACCOUNT_THREAT" not in file_reasons

    # Message Checks
    assert data_msg["asset_type"] == "message"
    msg_reasons = [r["rule"] for r in data_msg["reasons"]]
    assert "ACCOUNT_THREAT" in msg_reasons
    assert "USERINFO_AT_SYMBOL" not in msg_reasons
    assert "EXTENSION_MISMATCH_DECEPTION" not in msg_reasons
