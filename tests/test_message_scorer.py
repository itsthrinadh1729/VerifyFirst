"""Tests for message detection scoring."""
from backend.detection.message_detection.rules import MessageRuleResult
from backend.detection.message_detection.scorer import calculate_score_and_status


def test_scorer_no_rules():
    score, status = calculate_score_and_status([])
    assert score == 0
    assert status == "SAFE"


def test_scorer_urgency():
    rules = [
        MessageRuleResult(rule_id="URGENCY_LANGUAGE", weight=10, priority="P2", reason="")
    ]
    score, status = calculate_score_and_status(rules)
    assert score == 10
    assert status == "SAFE"


def test_scorer_credential_request():
    rules = [
        MessageRuleResult(rule_id="CREDENTIAL_REQUEST", weight=30, priority="P0", reason="")
    ]
    score, status = calculate_score_and_status(rules)
    assert score == 30
    assert status == "SUSPICIOUS"


def test_scorer_combinations_suspicious():
    # Credential (30) + account threat (25) + urgency (10) = 65
    rules = [
        MessageRuleResult(rule_id="CREDENTIAL_REQUEST", weight=30, priority="P0", reason=""),
        MessageRuleResult(rule_id="ACCOUNT_THREAT", weight=25, priority="P0", reason=""),
        MessageRuleResult(rule_id="URGENCY_LANGUAGE", weight=10, priority="P2", reason="")
    ]
    score, status = calculate_score_and_status(rules)
    assert score == 65
    assert status == "SUSPICIOUS"


def test_scorer_combinations_dangerous():
    # Credential (30) + OTP (30) + account threat (25) = 85
    rules = [
        MessageRuleResult(rule_id="CREDENTIAL_REQUEST", weight=30, priority="P0", reason=""),
        MessageRuleResult(rule_id="OTP_OR_PIN_REQUEST", weight=30, priority="P0", reason=""),
        MessageRuleResult(rule_id="ACCOUNT_THREAT", weight=25, priority="P0", reason="")
    ]
    score, status = calculate_score_and_status(rules)
    assert score == 85
    assert status == "DANGEROUS"


def test_scorer_cap():
    # raw score > 100
    rules = [
        MessageRuleResult(rule_id="CREDENTIAL_REQUEST", weight=30, priority="P0", reason=""),
        MessageRuleResult(rule_id="OTP_OR_PIN_REQUEST", weight=30, priority="P0", reason=""),
        MessageRuleResult(rule_id="FINANCIAL_REQUEST", weight=30, priority="P0", reason=""),
        MessageRuleResult(rule_id="ACCOUNT_THREAT", weight=25, priority="P0", reason="")
    ]
    score, status = calculate_score_and_status(rules)
    assert score == 100
    assert status == "DANGEROUS"
