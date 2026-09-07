"""Schemas for the Threat Intelligence Layer."""

from pydantic import BaseModel
from typing import Optional


class ThreatIntelResult(BaseModel):
    """Normalized result from any threat intelligence provider."""
    
    available: bool
    is_malicious: bool
    confidence: str  # "high", "low", "unknown"
    source: Optional[str]
    reason: Optional[str]

    @classmethod
    def unavailable(cls) -> "ThreatIntelResult":
        """Helper to return a safe unavailable result."""
        return cls(
            available=False,
            is_malicious=False,
            confidence="unknown",
            source=None,
            reason=None
        )
