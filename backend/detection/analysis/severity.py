"""Threat confidence and severity aggregation."""

from dataclasses import dataclass

from backend.detection.analysis.threat import ThreatAnalysisResult


@dataclass(frozen=True)
class ThreatAssessment:
    """Aggregated threat assessment."""

    severity: str | None
    confidence: float
    categories: tuple[str, ...]
    patterns: tuple[str, ...]


def aggregate_severity(
    analysis: ThreatAnalysisResult,
) -> str | None:
    """Return the highest severity supported by the analysis."""

    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
    }

    severities = [
        evidence.severity
        for evidence in analysis.evidence
    ]

    severities.extend(
        pattern.severity
        for pattern in analysis.patterns
    )

    if not severities:
        return None

    return max(
        severities,
        key=lambda severity: severity_rank[severity],
    )


def assess_threat(
    analysis: ThreatAnalysisResult,
) -> ThreatAssessment:
    """Aggregate threat evidence without changing risk scoring."""

    return ThreatAssessment(
        severity=analysis.highest_severity,
        confidence=analysis.overall_confidence,
        categories=analysis.categories,
        patterns=analysis.pattern_ids,
    )
