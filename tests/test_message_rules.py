"""Tests for message detection rules."""
from backend.detection.message_detection.schemas import MessageFeatures
from backend.detection.message_detection.rules import evaluate_rules


def test_individual_rules():
    # Credential request
    rules = evaluate_rules(MessageFeatures(has_credential_request=True))
    assert len(rules) == 1
    assert rules[0].rule_id == "CREDENTIAL_REQUEST"
    assert rules[0].weight == 30

    # OTP request
    rules = evaluate_rules(MessageFeatures(has_otp_request=True))
    assert len(rules) == 1
    assert rules[0].rule_id == "OTP_OR_PIN_REQUEST"

    # Financial request
    rules = evaluate_rules(MessageFeatures(has_financial_request=True))
    assert len(rules) == 1
    assert rules[0].rule_id == "FINANCIAL_REQUEST"

    # Account threat
    rules = evaluate_rules(MessageFeatures(has_account_threat=True))
    assert len(rules) == 1
    assert rules[0].rule_id == "ACCOUNT_THREAT"

    # Impersonation
    rules = evaluate_rules(MessageFeatures(has_impersonation_language=True))
    assert len(rules) == 1
    assert rules[0].rule_id == "IMPERSONATION_LANGUAGE"

    # Prize
    rules = evaluate_rules(MessageFeatures(has_prize_claim=True))
    assert len(rules) == 1
    assert rules[0].rule_id == "PRIZE_REWARD_SCAM"

    # Social engineering
    rules = evaluate_rules(MessageFeatures(has_social_engineering_pattern=True))
    assert len(rules) == 1
    assert rules[0].rule_id == "SOCIAL_ENGINEERING_PATTERN"

    # CTA
    rules = evaluate_rules(MessageFeatures(has_suspicious_cta=True))
    assert len(rules) == 1
    assert rules[0].rule_id == "SUSPICIOUS_CTA"

    # Urgency
    rules = evaluate_rules(MessageFeatures(has_urgent_language=True))
    assert len(rules) == 1
    assert rules[0].rule_id == "URGENCY_LANGUAGE"


def test_negative_cases():
    rules = evaluate_rules(MessageFeatures())
    assert len(rules) == 0


def test_combinations():
    # threat + credential
    rules = evaluate_rules(MessageFeatures(has_account_threat=True, has_credential_request=True))
    assert len(rules) == 2
    rule_ids = {r.rule_id for r in rules}
    assert rule_ids == {"ACCOUNT_THREAT", "CREDENTIAL_REQUEST"}

    # threat + urgency
    rules = evaluate_rules(MessageFeatures(has_account_threat=True, has_urgent_language=True))
    assert len(rules) == 2
    rule_ids = {r.rule_id for r in rules}
    assert rule_ids == {"ACCOUNT_THREAT", "URGENCY_LANGUAGE"}

    # impersonation + urgency
    rules = evaluate_rules(MessageFeatures(has_impersonation_language=True, has_urgent_language=True))
    assert len(rules) == 2
    rule_ids = {r.rule_id for r in rules}
    assert rule_ids == {"IMPERSONATION_LANGUAGE", "URGENCY_LANGUAGE"}
