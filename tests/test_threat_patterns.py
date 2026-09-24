from backend.detection.analysis.analyzer import analyze_threats
from backend.detection.analysis.patterns import correlate_patterns
from backend.detection.engine.scorer import analyze_url_security


def test_domain_impersonation_pattern():
    result = analyze_url_security(
        "https://paypal.com.attacker.com"
    )

    analysis = analyze_threats(result)
    correlated = correlate_patterns(analysis)

    assert "DOMAIN_IMPERSONATION" in correlated.pattern_ids


def test_credential_phishing_pattern():
    result = analyze_url_security(
        "https://www.google.com@paypal-login.com/"
    )

    analysis = analyze_threats(result)
    correlated = correlate_patterns(analysis)

    assert "CREDENTIAL_PHISHING" in correlated.pattern_ids


def test_path_manipulation_pattern():
    result = analyze_url_security(
        "https://example.com/%2e%2e/%2e%2e/etc/passwd"
    )

    analysis = analyze_threats(result)
    correlated = correlate_patterns(analysis)

    assert "PATH_MANIPULATION" in correlated.pattern_ids


def test_redirect_with_brand_creates_credential_pattern():
    result = analyze_url_security(
        "https://paypal-login.example.com/login"
        "?next=https://attacker.example"
    )

    analysis = analyze_threats(result)
    correlated = correlate_patterns(analysis)

    assert "CREDENTIAL_PHISHING" in correlated.pattern_ids


def test_safe_domain_has_no_patterns():
    result = analyze_url_security(
        "https://login.paypal.com"
    )

    analysis = analyze_threats(result)
    correlated = correlate_patterns(analysis)

    assert correlated.patterns == ()


def test_pattern_correlation_does_not_change_score():
    result = analyze_url_security(
        "https://paypal.com.attacker.com"
    )

    original_score = result.risk_score
    original_status = result.status

    analysis = analyze_threats(result)
    correlate_patterns(analysis)

    assert result.risk_score == original_score
    assert result.status == original_status
