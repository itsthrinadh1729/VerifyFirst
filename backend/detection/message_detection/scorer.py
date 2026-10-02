"""Message detection scoring logic."""
from typing import List, Literal, Tuple

from .rules import MessageRuleResult

# Calibrated normalization ceiling for message risk scoring.
#
# The theoretical sum of all message rule weights is 195, but in practice
# three P0 rules (CREDENTIAL + OTP + FINANCIAL = 90) with supporting
# indicators represent the realistic maximum. A ceiling of 100 preserves
# meaningful classification boundaries for single and multi-indicator messages.
MAX_MESSAGE_RAW_SCORE: int = 100


def normalize_message_risk_score(raw_score: int, max_raw: int) -> int:
    """Normalize a raw weight sum into a continuous 0–100 risk score.

    Formula: round(raw_score / max_raw * 100), clamped to [0, 100].
    """
    if max_raw <= 0:
        return min(100, max(0, raw_score))
    normalized = (raw_score / max_raw) * 100
    return max(0, min(100, round(normalized)))


def calculate_score_and_status(rules: List[MessageRuleResult]) -> Tuple[int, Literal["SAFE", "SUSPICIOUS", "DANGEROUS"]]:
    """Calculates the final risk score and classification based on triggered rules.
    
    Scoring boundaries:
    0-25: SAFE
    26-65: SUSPICIOUS
    66-100: DANGEROUS
    """
    raw_score = sum(r.weight for r in rules)
    score = normalize_message_risk_score(raw_score, MAX_MESSAGE_RAW_SCORE)
    
    if score <= 25:
        status = "SAFE"
    elif score <= 65:
        status = "SUSPICIOUS"
    else:
        status = "DANGEROUS"
        
    return score, status

