"""Message detection scoring logic."""
from typing import List, Literal, Tuple

from .rules import MessageRuleResult


def calculate_score_and_status(rules: List[MessageRuleResult]) -> Tuple[int, Literal["SAFE", "SUSPICIOUS", "DANGEROUS"]]:
    """Calculates the final risk score and classification based on triggered rules.
    
    Scoring boundaries:
    0-25: SAFE
    26-65: SUSPICIOUS
    66-100: DANGEROUS
    """
    raw_score = sum(r.weight for r in rules)
    score = min(raw_score, 100)
    
    if score <= 25:
        status = "SAFE"
    elif score <= 65:
        status = "SUSPICIOUS"
    else:
        status = "DANGEROUS"
        
    return score, status
