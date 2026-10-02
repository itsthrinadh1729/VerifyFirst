from backend.detection.analysis.analyzer import analyze_threats
from backend.detection.analysis.context import build_threat_context
from backend.detection.analysis.patterns import correlate_patterns
from backend.detection.analysis.severity import assess_threat
from backend.detection.engine.scorer import analyze_url_security


def _analyze(url: str):
    detection = analyze_url_security(url)
    analysis = analyze_threats(detection)
    analysis = correlate_patterns(analysis)
    assessment = assess_threat(analysis)
    return detection, analysis, assessment


def test_safe_url_has_no_context():
    detection, analysis, assessment = _analyze(
        "https://login.paypal.com"
    )

    context = build_threat_context(analysis, assessment)

    assert detection.status == "SAFE"
    assert context is None


def test_domain_impersonation_context():
    detection, analysis, assessment = _analyze(
        "https://paypal.com.attacker.com"
    )

    context = build_threat_context(analysis, assessment)

    # BRAND_IMPERSONATION(35) + DECEPTIVE_DOMAIN_STRUCTURE(25) = raw 60 -> normalized 46
    assert detection.risk_score == 46
    assert detection.status == "SUSPICIOUS"

    assert assessment.severity == "HIGH"
    assert assessment.confidence == 0.95
    assert "DOMAIN_IMPERSONATION" in assessment.patterns

    assert context is not None
    assert context.title == "Domain impersonation detected"
    assert context.summary
    assert context.technical_details
    assert context.user_impact
    assert context.recommended_action


def test_userinfo_context():
    detection, analysis, assessment = _analyze(
        "https://www.google.com@paypal-login.com/"
    )

    context = build_threat_context(analysis, assessment)

    assert context is not None
    assert (
        "USERINFO_DECEPTION" in assessment.patterns
    )
    assert context.title == "Deceptive URL structure detected"


def test_path_manipulation_context():
    detection, analysis, assessment = _analyze(
        "https://example.com/%2e%2e/%2e%2e/etc/passwd"
    )

    context = build_threat_context(analysis, assessment)

    assert context is not None
    assert "PATH_MANIPULATION" in assessment.patterns
    assert context.title == "Suspicious path manipulation detected"


def test_context_is_score_neutral():
    url = "https://paypal.com.attacker.com"

    detection_before, analysis, assessment = _analyze(url)

    context = build_threat_context(
        analysis,
        assessment,
    )

    detection_after = analyze_url_security(url)

    assert context is not None

    assert detection_after.risk_score == detection_before.risk_score
    assert detection_after.status == detection_before.status
    assert detection_after.reasons == detection_before.reasons


def test_technical_details_are_unique():
    _, analysis, assessment = _analyze(
        "https://paypal.com.attacker.com"
    )

    context = build_threat_context(
        analysis,
        assessment,
    )

    assert context is not None

    assert len(context.technical_details) == len(
        set(context.technical_details)
    )
