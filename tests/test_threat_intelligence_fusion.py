from backend.detection.analysis.fusion import (
    build_intelligence_evidence,
    fuse_evidence,
)
from backend.detection.intelligence.schemas import (
    ThreatIntelResult,
)
from backend.detection.engine.scorer import analyze_url_security


def test_malicious_intelligence_creates_fusion_evidence():
    result = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="google_safe_browsing",
        reason="Known phishing URL",
    )

    evidence = build_intelligence_evidence(result)

    assert evidence is not None
    assert evidence.source == "google_safe_browsing"
    assert evidence.rule_id == "THREAT_INTELLIGENCE_MATCH"
    assert evidence.confidence == "high"
    assert evidence.message == "Known phishing URL"


def test_clean_intelligence_creates_no_fusion_evidence():
    result = ThreatIntelResult(
        available=True,
        is_malicious=False,
        confidence="low",
        source="google_safe_browsing",
        reason=None,
    )

    evidence = build_intelligence_evidence(result)

    assert evidence is None


def test_unavailable_intelligence_creates_no_fusion_evidence():
    result = ThreatIntelResult.unavailable()

    evidence = build_intelligence_evidence(result)

    assert evidence is None


def test_fusion_does_not_duplicate_intelligence_evidence():
    heuristic = analyze_url_security("https://example.com")

    intel = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="google_safe_browsing",
        reason="Known threat",
    )

    first = fuse_evidence(heuristic, intel)
    second = fuse_evidence(first, intel)

    matches = [
        reason
        for reason in second.reasons
        if reason.rule == "THREAT_INTELLIGENCE_MATCH"
    ]

    assert len(matches) == 1
    assert second.risk_score == 100
    assert second.status == "DANGEROUS"


def test_intelligence_match_preserves_heuristic_reasons():
    url = "https://paypal.com.attacker.com"
    heuristic = analyze_url_security(url)

    intel = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="google_safe_browsing",
        reason="Known threat",
    )

    fused = fuse_evidence(heuristic, intel)

    heuristic_rules = {reason.rule for reason in heuristic.reasons}
    fused_rules = {reason.rule for reason in fused.reasons}

    assert heuristic_rules.issubset(fused_rules)
    assert "THREAT_INTELLIGENCE_MATCH" in fused_rules


def test_clean_intelligence_preserves_heuristic_result():
    url = "https://paypal.com.attacker.com"
    heuristic = analyze_url_security(url)

    intel = ThreatIntelResult(
        available=True,
        is_malicious=False,
        confidence="low",
        source="google_safe_browsing",
        reason=None,
    )

    fused = fuse_evidence(heuristic, intel)

    assert fused.status == heuristic.status
    assert fused.risk_score == heuristic.risk_score
    assert fused.reasons == heuristic.reasons


def test_unavailable_intelligence_preserves_heuristics():
    url = "https://paypal.com.attacker.com"
    heuristic = analyze_url_security(url)

    intel = ThreatIntelResult.unavailable()

    fused = fuse_evidence(heuristic, intel)

    assert fused == heuristic


def test_intelligence_match_overrides_safe_heuristic():
    url = "https://example.com"
    heuristic = analyze_url_security(url)

    assert heuristic.status == "SAFE"

    intel = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="google_safe_browsing",
        reason="Known malicious URL",
    )

    fused = fuse_evidence(heuristic, intel)

    assert fused.status == "DANGEROUS"
    assert fused.risk_score == 100


def test_intelligence_source_is_available_before_fusion():
    intel = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="google_safe_browsing",
        reason="Known phishing URL",
    )

    evidence = build_intelligence_evidence(intel)

    assert evidence.source == "google_safe_browsing"


def test_complete_intelligence_fusion_chain():
    url = "https://example.com"
    heuristic = analyze_url_security(url)

    assert heuristic.status == "SAFE"

    intel = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="google_safe_browsing",
        reason="Known malicious URL",
    )

    evidence = build_intelligence_evidence(intel)

    assert evidence is not None

    fused = fuse_evidence(heuristic, intel)

    assert fused.status == "DANGEROUS"
    assert fused.risk_score == 100

    assert any(
        reason.rule == "THREAT_INTELLIGENCE_MATCH"
        for reason in fused.reasons
    )
