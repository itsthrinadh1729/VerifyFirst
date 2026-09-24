from backend.detection.intelligence.providers import (
    normalize_confidence,
    normalize_threat_intel_result,
)
from backend.detection.analysis.fusion import fuse_evidence
from backend.detection.engine.scorer import analyze_url_security


def test_normalize_high_confidence():
    assert normalize_confidence("high") == "high"
    assert normalize_confidence(0.95) == "high"


def test_normalize_medium_confidence():
    assert normalize_confidence("medium") == "medium"
    assert normalize_confidence(0.70) == "medium"


def test_normalize_low_confidence():
    assert normalize_confidence("low") == "low"
    assert normalize_confidence(0.20) == "low"


def test_normalize_unknown_confidence():
    assert normalize_confidence("unknown") == "unknown"
    assert normalize_confidence("invalid") == "unknown"
    assert normalize_confidence(None) == "unknown"


def test_normalize_malicious_result():
    result = normalize_threat_intel_result(
        available=True,
        is_malicious=True,
        confidence=0.95,
        source="test_provider",
        reason="Known phishing URL",
    )

    assert result.available is True
    assert result.is_malicious is True
    assert result.confidence == "high"
    assert result.source == "test_provider"
    assert result.reason == "Known phishing URL"


def test_normalize_clean_result():
    result = normalize_threat_intel_result(
        available=True,
        is_malicious=False,
        confidence=0.20,
        source="test_provider",
        reason=None,
    )

    assert result.available is True
    assert result.is_malicious is False
    assert result.confidence == "low"
    assert result.source == "test_provider"


def test_unavailable_result_cannot_be_malicious():
    result = normalize_threat_intel_result(
        available=False,
        is_malicious=True,
        confidence=1.0,
        source="test_provider",
        reason="Provider failure",
    )

    assert result.available is False
    assert result.is_malicious is False
    assert result.confidence == "unknown"
    assert result.source is None
    assert result.reason is None


def test_confidence_boundaries():
    assert normalize_confidence(0.80) == "high"
    assert normalize_confidence(0.79) == "medium"

    assert normalize_confidence(0.50) == "medium"
    assert normalize_confidence(0.49) == "low"

    assert normalize_confidence(0.0) == "low"


def test_invalid_numeric_confidence():
    assert normalize_confidence(-0.1) == "unknown"
    assert normalize_confidence(1.1) == "unknown"


def test_confidence_strings_are_case_insensitive():
    assert normalize_confidence("HIGH") == "high"
    assert normalize_confidence(" Medium ") == "medium"
    assert normalize_confidence("LOW") == "low"


def test_source_is_preserved():
    result = normalize_threat_intel_result(
        available=True,
        is_malicious=True,
        confidence="high",
        source="google_safe_browsing",
        reason="Threat match",
    )

    assert result.source == "google_safe_browsing"


def test_normalized_malicious_result_fuses_to_dangerous():
    heuristic = analyze_url_security(
        "https://example.com"
    )

    intel = normalize_threat_intel_result(
        available=True,
        is_malicious=True,
        confidence=0.95,
        source="test_provider",
        reason="Known threat",
    )

    fused = fuse_evidence(
        heuristic,
        intel,
    )

    assert fused.status == "DANGEROUS"
    assert fused.risk_score == 100


def test_normalized_unavailable_result_preserves_heuristic():
    heuristic = analyze_url_security(
        "https://example.com"
    )

    intel = normalize_threat_intel_result(
        available=False,
        is_malicious=True,
        confidence=1.0,
        source="test_provider",
        reason="Provider unavailable",
    )

    fused = fuse_evidence(
        heuristic,
        intel,
    )

    assert fused.status == heuristic.status
    assert fused.risk_score == heuristic.risk_score
