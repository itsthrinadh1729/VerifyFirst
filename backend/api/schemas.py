"""API schemas and URL input validation for VerifyFirst."""

import unicodedata
from urllib.parse import urlsplit
from pydantic import BaseModel, Field, field_validator


class AnalyzeRequest(BaseModel):
    """Request model for URL analysis endpoint."""

    url: str = Field(..., description="The URL to analyze", min_length=1, max_length=2048)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("URL cannot be empty or whitespace only.")

        if len(trimmed) > 2048:
            raise ValueError("URL exceeds maximum allowed length of 2048 characters.")

        # Reject control characters (ASCII 0-31, 127) and Unicode control categories
        for char in trimmed:
            code = ord(char)
            if code < 32 or code == 127 or unicodedata.category(char).startswith("C"):
                raise ValueError("URL contains illegal control characters or null bytes.")

        try:
            parsed = urlsplit(trimmed)
        except Exception as exc:
            raise ValueError("Malformed URL.") from exc

        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"Unsupported scheme '{parsed.scheme}'. Only http and https are allowed.")

        if not parsed.netloc or not parsed.hostname:
            raise ValueError("URL must include a valid hostname/domain.")

        return trimmed


class ThreatContextResponse(BaseModel):
    """Structured explanation of the threat and user impact."""

    title: str = Field(..., description="High-level threat title")
    summary: str = Field(..., description="Clear explanation of the detection")
    technical_details: list[str] = Field(default_factory=list, description="Technical rule triggers")
    user_impact: str = Field(..., description="Explanation of consequences")
    recommended_action: str = Field(..., description="What the user should do")


class DetectionReasonItem(BaseModel):
    """Structured detection reason with rule identifier and human-readable explanation."""

    rule: str = Field(..., description="Rule identifier")
    message: str = Field(..., description="Human-readable explanation of why the rule triggered")


class AnalyzeResponse(BaseModel):
    """Response model for URL analysis endpoint."""

    status: str = Field(..., description="Risk classification: SAFE, SUSPICIOUS, DANGEROUS, or ANALYSIS_UNAVAILABLE")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0 to 100")
    reasons: list[DetectionReasonItem] = Field(default_factory=list, description="List of detection reasons or indicators")
    threat_context: ThreatContextResponse | None = Field(default=None, description="Detailed explanation of the threat")


# ── File Analysis Schemas (Phase 2) ──────────────────────────────────────


class FileAnalyzeRequest(BaseModel):
    """Request model for file analysis endpoint."""

    filename: str = Field(..., description="The original filename to analyze", min_length=1, max_length=1024)
    mime_type: str = Field(default="", description="MIME type if available")
    file_size: int = Field(default=0, ge=0, description="File size in bytes")
    source: str = Field(default="whatsapp", description="Source of the file")

    @field_validator("filename")
    @classmethod
    def validate_filename(cls, v: str) -> str:
        trimmed = v.strip()
        if not trimmed:
            raise ValueError("Filename cannot be empty or whitespace only.")
        if len(trimmed) > 1024:
            raise ValueError("Filename exceeds maximum allowed length of 1024 characters.")
        # Reject control characters
        for char in trimmed:
            code = ord(char)
            if code < 32 or code == 127:
                raise ValueError("Filename contains illegal control characters.")
        return trimmed


class FileAnalyzeResponse(BaseModel):
    """Response model for file analysis endpoint."""

    status: str = Field(..., description="Risk classification: SAFE, SUSPICIOUS, or DANGEROUS")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0 to 100")
    reasons: list[DetectionReasonItem] = Field(default_factory=list, description="List of detection reasons")
    filename: str = Field(..., description="The analyzed filename")
    asset_type: str = Field(default="file", description="Asset type identifier")

