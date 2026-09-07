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


class DetectionReasonItem(BaseModel):
    """Structured detection reason with rule identifier and human-readable explanation."""

    rule: str = Field(..., description="Rule identifier")
    message: str = Field(..., description="Human-readable explanation of why the rule triggered")


class AnalyzeResponse(BaseModel):
    """Response model for URL analysis endpoint."""

    status: str = Field(..., description="Risk classification: SAFE, SUSPICIOUS, DANGEROUS, or ANALYSIS_UNAVAILABLE")
    risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0 to 100")
    reasons: list[DetectionReasonItem] = Field(default_factory=list, description="List of detection reasons or indicators")

