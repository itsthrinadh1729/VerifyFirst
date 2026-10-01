"""Tests for message detection feature extraction."""

from backend.detection.message_detection.features import extract_features


def test_has_urgent_language():
    features = extract_features("You must ACT NOW to save your account.")
    assert features.has_urgent_language is True

    features = extract_features("Hello, how are you?")
    assert features.has_urgent_language is False


def test_has_financial_request():
    features = extract_features("Please send money to my account.")
    assert features.has_financial_request is True

    features = extract_features("Can we talk about the payment required?")
    assert features.has_financial_request is True


def test_has_credential_request():
    features = extract_features("Please enter your password below.")
    assert features.has_credential_request is True


def test_has_otp_request():
    features = extract_features("Share OTP with me for verification.")
    assert features.has_otp_request is True


def test_has_impersonation_language():
    features = extract_features("This is your bank calling.")
    assert features.has_impersonation_language is True


def test_has_account_threat():
    features = extract_features("Your account will be suspended if you don't reply.")
    assert features.has_account_threat is True


def test_has_prize_claim():
    features = extract_features("Congratulations! You won a free gift.")
    assert features.has_prize_claim is True


def test_has_suspicious_cta():
    features = extract_features("Please click here to continue.")
    assert features.has_suspicious_cta is True


def test_social_engineering_phrase():
    features = extract_features("Do not tell anyone about this transfer.")
    assert features.has_social_engineering_pattern is True


def test_social_engineering_combinations():
    # Impersonation + Urgency
    features = extract_features("This is WhatsApp support. You must act now!")
    assert features.has_impersonation_language is True
    assert features.has_urgent_language is True
    assert features.has_social_engineering_pattern is True

    # Account threat + Credential
    features = extract_features("Your account will be suspended. Please verify your account.")
    assert features.has_account_threat is True
    assert features.has_credential_request is True
    assert features.has_social_engineering_pattern is True

    # Prize claim + Suspicious CTA (does not trigger combo_se but triggers individual features)
    # The current combo logic doesn't flag this specifically as combo_se unless we add it
    features = extract_features("You won! Click here to claim your prize.")
    assert features.has_prize_claim is True
    assert features.has_suspicious_cta is True
    assert features.has_social_engineering_pattern is False
