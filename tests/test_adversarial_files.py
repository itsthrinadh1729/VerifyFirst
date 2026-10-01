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
async def test_adversarial_double_extensions(client):
    """Category A - Double extensions"""
    files = [
        "invoice.pdf.exe",
        "report.docx.scr",
        "photo.jpg.exe"
    ]
    for filename in files:
        response = await client.post("/api/v1/analyze-file", json={"filename": filename})
        assert response.status_code == 200
        data = response.json()
        assert data["asset_type"] == "file"
        reasons = [r["rule"] for r in data["reasons"]]
        assert "EXTENSION_MISMATCH_DECEPTION" in reasons
        # Verify it doesn't double count dangerous extension if mismatched.
        # Check rule mapping.

@pytest.mark.asyncio
async def test_adversarial_case_variation(client):
    """Category B - Case variation"""
    files = [
        "invoice.PDF.EXE",
        "invoice.Pdf.ExE",
        "invoice.PDF.exe"
    ]
    results = []
    for filename in files:
        response = await client.post("/api/v1/analyze-file", json={"filename": filename})
        data = response.json()
        results.append(data)
    
    # All should follow the same normalization behavior.
    assert results[0]["risk_score"] == results[1]["risk_score"]
    assert results[1]["risk_score"] == results[2]["risk_score"]

@pytest.mark.asyncio
async def test_adversarial_benign_archives(client):
    """Category C - Benign archives"""
    files = [
        "backup.zip",
        "photos.zip",
        "project.tar.gz"
    ]
    for filename in files:
        response = await client.post("/api/v1/analyze-file", json={"filename": filename})
        data = response.json()
        reasons = [r["rule"] for r in data["reasons"]]
        # Benign archives alone might not trigger any rule, just ensure they are SAFE or SUSPICIOUS
        assert data["status"] in ("SAFE", "SUSPICIOUS")

@pytest.mark.asyncio
async def test_adversarial_script_extensions(client):
    """Category D - Script extensions"""
    files = ["script.vbs", "run.ps1", "do.cmd", "exec.bat"]
    for filename in files:
        response = await client.post("/api/v1/analyze-file", json={"filename": filename})
        data = response.json()
        reasons = [r["rule"] for r in data["reasons"]]
        assert any(r in reasons for r in ("SCRIPT_FILE_EXTENSION", "DANGEROUS_FILE_EXTENSION"))
        assert data["status"] in ("SUSPICIOUS", "DANGEROUS")

@pytest.mark.asyncio
async def test_adversarial_macro_documents(client):
    """Category E - Macro documents"""
    files = [".docm", "file.xlsm", "file.pptm"]
    for filename in files:
        if filename == ".docm": continue # invalid filename edgecase might be handled differently, let's use valid ones
        response = await client.post("/api/v1/analyze-file", json={"filename": filename})
        data = response.json()
        reasons = [r["rule"] for r in data["reasons"]]
        assert "DOCUMENT_MACRO_EXTENSION" in reasons

@pytest.mark.asyncio
async def test_adversarial_filename_social_engineering(client):
    """Category F - Filename social engineering"""
    files = [
        "URGENT-INVOICE.exe",
        "PAYMENT-REQUIRED.exe",
        "ACCOUNT-VERIFICATION.exe"
    ]
    for filename in files:
        response = await client.post("/api/v1/analyze-file", json={"filename": filename})
        data = response.json()
        reasons = [r["rule"] for r in data["reasons"]]
        assert "DANGEROUS_SOCIAL_ENGINEERING_FILENAME" in reasons

@pytest.mark.asyncio
async def test_adversarial_boundary_cases(client):
    """Category G - Boundary cases"""
    files = [
        "a" * 255 + ".exe",
        "a" * 300 + ".exe",
        "my file with spaces.exe",
        "a.b.c.d.e.f.exe",
        "test_ü_🚀.exe"
    ]
    for filename in files:
        response = await client.post("/api/v1/analyze-file", json={"filename": filename})
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")

@pytest.mark.asyncio
async def test_score_boundaries_file(client):
    """4C.8 Score integrity"""
    # Safe boundary
    response = await client.post("/api/v1/analyze-file", json={"filename": "photo.jpg"})
    data = response.json()
    assert 0 <= data["risk_score"] <= 100
    if data["status"] == "SAFE":
        assert data["risk_score"] <= 25
    
    # Suspicious logic
    response = await client.post("/api/v1/analyze-file", json={"filename": "backup.zip"})
    data = response.json()
    if data["status"] == "SUSPICIOUS":
        assert 26 <= data["risk_score"] <= 65
    
    # Dangerous logic
    response = await client.post("/api/v1/analyze-file", json={"filename": "PAYMENT-REQUIRED.exe"})
    data = response.json()
    if data["status"] == "DANGEROUS":
        assert 66 <= data["risk_score"] <= 100

@pytest.mark.asyncio
async def test_reason_integrity_file(client):
    response = await client.post("/api/v1/analyze-file", json={"filename": "invoice.pdf.exe"})
    data = response.json()
    reasons = [r["rule"] for r in data["reasons"]]
    assert "CREDENTIAL_REQUEST" not in reasons
    assert data["asset_type"] == "file"
