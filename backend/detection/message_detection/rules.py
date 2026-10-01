"""Message detection rules for VerifyFirst."""
from dataclasses import dataclass
from typing import List

from .schemas import MessageFeatures


@dataclass(frozen=True)
class MessageRuleResult:
    rule_id: str
    weight: int
    priority: str
    reason: str


def evaluate_rules(features: MessageFeatures) -> List[MessageRuleResult]:
    """Evaluates features against detection rules to produce evidence."""
    rules = []

    if features.has_credential_request:
        rules.append(MessageRuleResult(
            rule_id="CREDENTIAL_REQUEST",
            weight=30,
            priority="P0",
            reason="Message requests password or credentials."
        ))

    if features.has_otp_request:
        rules.append(MessageRuleResult(
            rule_id="OTP_OR_PIN_REQUEST",
            weight=30,
            priority="P0",
            reason="Message requests an OTP, PIN, or verification code."
        ))

    if features.has_financial_request:
        rules.append(MessageRuleResult(
            rule_id="FINANCIAL_REQUEST",
            weight=30,
            priority="P0",
            reason="Message requests a financial transfer or payment."
        ))

    if features.has_account_threat:
        rules.append(MessageRuleResult(
            rule_id="ACCOUNT_THREAT",
            weight=25,
            priority="P0",
            reason="Message contains a threat to account security or access."
        ))

    if features.has_impersonation_language:
        rules.append(MessageRuleResult(
            rule_id="IMPERSONATION_LANGUAGE",
            weight=20,
            priority="P1",
            reason="Message uses language typical of official support or administration."
        ))

    if features.has_prize_claim:
        rules.append(MessageRuleResult(
            rule_id="PRIZE_REWARD_SCAM",
            weight=20,
            priority="P1",
            reason="Message claims the recipient has won a prize or reward."
        ))

    if features.has_social_engineering_pattern:
        rules.append(MessageRuleResult(
            rule_id="SOCIAL_ENGINEERING_PATTERN",
            weight=15,
            priority="P1",
            reason="Message exhibits correlated social engineering or manipulation patterns."
        ))

    if features.has_suspicious_cta:
        rules.append(MessageRuleResult(
            rule_id="SUSPICIOUS_CTA",
            weight=15,
            priority="P1",
            reason="Message contains a suspicious call to action."
        ))

    if features.has_urgent_language:
        rules.append(MessageRuleResult(
            rule_id="URGENCY_LANGUAGE",
            weight=10,
            priority="P2",
            reason="Message contains urgent language attempting to force quick action."
        ))

    return rules
