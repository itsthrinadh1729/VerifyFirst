"""Tests for the Threat Analysis Engine."""

from backend.detection.analysis.analyzer import analyze_threats
from backend.detection.engine.scorer import analyze_url_security


def test_typosquatting_creates_domain_deception_evidence():
    result = analyze_url_security(
        "https://www.g00gle.com/search"
    )

    analysis = analyze_threats(result)

    assert "DOMAIN_DECEPTION" in analysis.categories

    evidence = analysis.evidence[0]

    assert "TYPOSQUATTING" in evidence.rule_ids
    assert evidence.severity == "MEDIUM"
    assert 0.0 <= evidence.confidence <= 1.0


def test_combined_domain_evidence_has_higher_severity():
    result = analyze_url_security(
        "https://paypal.com.attacker.com"
    )

    analysis = analyze_threats(result)

    assert "DOMAIN_DECEPTION" in analysis.categories

    evidence = next(
        item
        for item in analysis.evidence
        if item.category == "DOMAIN_DECEPTION"
    )

    assert "BRAND_IMPERSONATION" in evidence.rule_ids
    assert "DECEPTIVE_DOMAIN_STRUCTURE" in evidence.rule_ids
    assert evidence.severity == "HIGH"
    assert evidence.confidence == 0.95


def test_deceptive_userinfo_creates_userinfo_evidence():
    result = analyze_url_security(
        "https://www.google.com@malicious-site.com/"
    )

    analysis = analyze_threats(result)

    assert "USERINFO_DECEPTION" in analysis.categories

    evidence = next(
        item
        for item in analysis.evidence
        if item.category == "USERINFO_DECEPTION"
    )

    assert "USERINFO_AT_SYMBOL" in evidence.rule_ids
    assert "DECEPTIVE_USERINFO_DESTINATION" in evidence.rule_ids
    assert evidence.severity == "HIGH"


def test_encoded_traversal_creates_path_traversal_evidence():
    result = analyze_url_security(
        "https://example.com/%2e%2e/%2e%2e/etc/passwd"
    )

    analysis = analyze_threats(result)

    assert "PATH_TRAVERSAL" in analysis.categories

    evidence = next(
        item
        for item in analysis.evidence
        if item.category == "PATH_TRAVERSAL"
    )

    assert evidence.severity == "HIGH"
    assert evidence.confidence == 0.90


def test_external_redirect_creates_redirect_evidence():
    result = analyze_url_security(
        "https://example.com/login?next=https://attacker.com"
    )

    analysis = analyze_threats(result)

    assert "REDIRECT_ABUSE" in analysis.categories

    evidence = next(
        item
        for item in analysis.evidence
        if item.category == "REDIRECT_ABUSE"
    )

    assert "EXTERNAL_REDIRECT_DESTINATION" in evidence.rule_ids


def test_ip_address_creates_network_anomaly():
    result = analyze_url_security(
        "https://192.168.1.100/login"
    )

    analysis = analyze_threats(result)

    assert "NETWORK_ANOMALY" in analysis.categories


def test_safe_domain_has_no_threat_evidence():
    result = analyze_url_security(
        "https://login.paypal.com"
    )

    analysis = analyze_threats(result)

    assert analysis.evidence == ()
    assert analysis.categories == ()
    assert analysis.highest_severity is None


def test_threat_analysis_does_not_change_detection_result():
    result = analyze_url_security(
        "https://paypal.com.attacker.com"
    )

    original_status = result.status
    original_score = result.risk_score
    original_reasons = result.reasons

    analyze_threats(result)

    assert result.status == original_status
    assert result.risk_score == original_score
    assert result.reasons == original_reasons
