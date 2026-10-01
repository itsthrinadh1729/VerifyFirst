"""API integration tests for the file analysis endpoint (Phase 2F)."""

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
async def test_file_safe_pdf(client):
    response = await client.post("/api/v1/analyze-file", json={"filename": "document.pdf"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SAFE"
    assert data["risk_score"] == 0
    assert data["asset_type"] == "file"
    assert data["filename"] == "document.pdf"


@pytest.mark.asyncio
async def test_file_dangerous_exe(client):
    response = await client.post("/api/v1/analyze-file", json={"filename": "setup.exe"})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] > 25
    assert data["asset_type"] == "file"


@pytest.mark.asyncio
async def test_file_deceptive_double_extension(client):
    response = await client.post("/api/v1/analyze-file", json={"filename": "invoice.pdf.exe"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "DANGEROUS"
    assert data["risk_score"] >= 66
    assert len(data["reasons"]) > 0


@pytest.mark.asyncio
async def test_file_safe_jpg(client):
    response = await client.post("/api/v1/analyze-file", json={"filename": "photo.jpg"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SAFE"
    assert data["risk_score"] == 0
    assert len(data["reasons"]) == 0


@pytest.mark.asyncio
async def test_file_script(client):
    response = await client.post("/api/v1/analyze-file", json={"filename": "helper.vbs"})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 26


@pytest.mark.asyncio
async def test_file_macro_document(client):
    response = await client.post("/api/v1/analyze-file", json={"filename": "report.docm"})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 25


@pytest.mark.asyncio
async def test_file_empty_filename_rejected(client):
    response = await client.post("/api/v1/analyze-file", json={"filename": "   "})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_file_optional_fields(client):
    response = await client.post("/api/v1/analyze-file", json={
        "filename": "photo.jpg",
        "mime_type": "image/jpeg",
        "file_size": 1024,
        "source": "whatsapp"
    })
    assert response.status_code == 200
    assert response.json()["status"] == "SAFE"


@pytest.mark.asyncio
async def test_url_endpoint_still_works(client):
    """Regression: existing URL endpoint is unaffected."""
    response = await client.post("/api/v1/analyze", json={"url": "https://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SAFE"


@pytest.mark.asyncio
async def test_file_reasons_structure(client):
    response = await client.post("/api/v1/analyze-file", json={"filename": "invoice.pdf.exe"})
    data = response.json()
    for reason in data["reasons"]:
        assert "rule" in reason
        assert "message" in reason
        assert isinstance(reason["rule"], str)
        assert isinstance(reason["message"], str)
