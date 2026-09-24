from backend.detection.analysis.analyzer import analyze_threats
from backend.detection.analysis.patterns import correlate_patterns
from backend.detection.analysis.severity import assess_threat
from backend.detection.engine.scorer import analyze_url_security


def _analyze(url: str):
    result = analyze_url_security(url)
    evidence = analyze_threats(result)
    return correlate_patterns(evidence)


def test_safe_url_has_zero_confidence():
    analysis = _analyze(
        "https://login.paypal.com"
    )

    assessment = assess_threat(analysis)

    assert assessment.severity is None
    assert assessment.confidence == 0.0
    assert assessment.categories == ()
    assert assessment.patterns == ()


def test_typosquatting_has_medium_threat_severity():
    analysis = _analyze(
        "https://www.g00gle.com/search"
    )

    assessment = assess_threat(analysis)

    assert assessment.severity == "MEDIUM"
    assert assessment.confidence == 0.80
    assert "DOMAIN_DECEPTION" in assessment.categories


def test_deceptive_domain_has_high_severity():
    analysis = _analyze(
        "https://paypal.com.attacker.com"
    )

    assessment = assess_threat(analysis)

    assert assessment.severity == "HIGH"
    assert assessment.confidence == 0.95
    assert "DOMAIN_IMPERSONATION" in assessment.patterns


def test_deceptive_userinfo_has_high_severity():
    analysis = _analyze(
        "https://www.google.com@paypal-login.com/"
    )

    assessment = assess_threat(analysis)

    assert assessment.severity == "HIGH"
    assert assessment.confidence == 0.95
    assert "USERINFO_DECEPTION" in assessment.patterns


def test_encoded_traversal_has_high_severity():
    analysis = _analyze(
        "https://example.com/%2e%2e/%2e%2e/etc/passwd"
    )

    assessment = assess_threat(analysis)

    assert assessment.severity == "HIGH"
    assert assessment.confidence == 0.90
    assert "PATH_MANIPULATION" in assessment.patterns


def test_assessment_does_not_change_detection_score():
    result = analyze_url_security(
        "https://paypal.com.attacker.com"
    )

    original_score = result.risk_score
    original_status = result.status

    analysis = analyze_threats(result)
    correlated = correlate_patterns(analysis)
    assess_threat(correlated)

    assert result.risk_score == original_score
    assert result.status == original_status
