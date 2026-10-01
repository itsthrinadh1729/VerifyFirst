"""Message detection schemas for VerifyFirst."""

from typing import List, Literal
from dataclasses import dataclass
from pydantic import BaseModel

class MessageAnalysisInput(BaseModel):
    message: str
    source: str = "whatsapp"


@dataclass
class MessageFeatures:
    has_urgent_language: bool = False
    has_financial_request: bool = False
    has_credential_request: bool = False
    has_otp_request: bool = False
    has_impersonation_language: bool = False
    has_account_threat: bool = False
    has_prize_claim: bool = False
    has_suspicious_cta: bool = False
    has_social_engineering_pattern: bool = False


@dataclass(frozen=True)
class MessageDetectionReason:
    rule: str
    message: str


class MessageDetectionResult(BaseModel):
    status: Literal["SAFE", "SUSPICIOUS", "DANGEROUS"]
    risk_score: int
    reasons: List[MessageDetectionReason]
    asset_type: Literal["message"] = "message"
