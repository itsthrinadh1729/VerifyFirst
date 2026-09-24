"""Threat analysis models for interpreting detection evidence."""

from dataclasses import dataclass


THREAT_CATEGORIES = frozenset({
    "BRAND_IMPERSONATION",
    "DOMAIN_DECEPTION",
    "URL_OBFUSCATION",
    "REDIRECT_ABUSE",
    "USERINFO_DECEPTION",
    "IDN_DECEPTION",
    "PATH_TRAVERSAL",
    "NETWORK_ANOMALY",
})


THREAT_SEVERITIES = frozenset({
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
})


THREAT_PATTERNS = frozenset({
    "CREDENTIAL_PHISHING",
    "DOMAIN_IMPERSONATION",
    "URL_OBFUSCATION",
    "REDIRECT_ABUSE",
    "USERINFO_DECEPTION",
    "IDN_DECEPTION",
    "PATH_MANIPULATION",
})


@dataclass(frozen=True)
class ThreatEvidence:
    """Structured interpretation of one or more detection signals."""

    category: str
    severity: str
    confidence: float
    rule_ids: tuple[str, ...]
    explanation: str

    def __post_init__(self) -> None:
        if self.category not in THREAT_CATEGORIES:
            raise ValueError(
                f"Unsupported threat category: {self.category}"
            )

        if self.severity not in THREAT_SEVERITIES:
            raise ValueError(
                f"Unsupported threat severity: {self.severity}"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Threat confidence must be between 0.0 and 1.0"
            )

        if not self.rule_ids:
            raise ValueError(
                "Threat evidence must reference at least one rule"
            )


@dataclass(frozen=True)
class ThreatPattern:
    """A correlated combination of threat evidence."""

    pattern_id: str
    severity: str
    confidence: float
    categories: tuple[str, ...]
    rule_ids: tuple[str, ...]
    explanation: str

    def __post_init__(self) -> None:
        if self.pattern_id not in THREAT_PATTERNS:
            raise ValueError(
                f"Unsupported threat pattern: {self.pattern_id}"
            )

        if self.severity not in THREAT_SEVERITIES:
            raise ValueError(
                f"Unsupported threat severity: {self.severity}"
            )

        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                "Threat pattern confidence must be between 0.0 and 1.0"
            )

        if not self.categories:
            raise ValueError(
                "Threat pattern must contain at least one category"
            )

        if not self.rule_ids:
            raise ValueError(
                "Threat pattern must reference at least one rule"
            )


@dataclass(frozen=True)
class ThreatAnalysisResult:
    """Complete threat interpretation produced from detection evidence."""

    evidence: tuple[ThreatEvidence, ...] = ()
    patterns: tuple[ThreatPattern, ...] = ()

    @property
    def categories(self) -> tuple[str, ...]:
        """Return unique threat categories in evidence order."""

        return tuple(
            dict.fromkeys(item.category for item in self.evidence)
        )

    @property
    def pattern_ids(self) -> tuple[str, ...]:
        """Return detected threat-pattern IDs."""

        return tuple(
            pattern.pattern_id
            for pattern in self.patterns
        )

    @property
    def highest_severity(self) -> str | None:
        """Return the highest severity represented by evidence or patterns."""

        severity_rank = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }

        severities = [
            item.severity
            for item in self.evidence
        ]

        severities.extend(
            pattern.severity
            for pattern in self.patterns
        )

        if not severities:
            return None

        return max(
            severities,
            key=lambda severity: severity_rank[severity],
        )

    @property
    def overall_confidence(self) -> float:
        """Aggregate confidence across evidence and correlated patterns."""

        if not self.evidence and not self.patterns:
            return 0.0

        evidence_confidences = [
            item.confidence
            for item in self.evidence
        ]

        pattern_confidences = [
            item.confidence
            for item in self.patterns
        ]

        all_confidences = (
            evidence_confidences +
            pattern_confidences
        )

        return round(
            max(all_confidences),
            2,
        )
