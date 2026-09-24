"""Schemas for the Threat Intelligence Layer."""

from pydantic import BaseModel
from typing import Optional
from enum import Enum
from dataclasses import dataclass


class ThreatIntelAvailability(str, Enum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"


class ThreatIntelFailure(str, Enum):
    TIMEOUT = "timeout"
    CONNECTION_ERROR = "connection_error"
    HTTP_ERROR = "http_error"
    INVALID_RESPONSE = "invalid_response"
    PROVIDER_ERROR = "provider_error"


@dataclass(frozen=True)
class ThreatIntelHealth:
    available: bool
    failure: ThreatIntelFailure | None = None


@dataclass(frozen=True)
class FusionEvidence:
    source: str
    rule_id: str
    message: str
    confidence: str


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
