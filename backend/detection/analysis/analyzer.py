"""Threat Analysis Engine.

Interprets deterministic detection rules into higher-level threat evidence.
This layer does not change the existing risk score.
"""

from backend.detection.engine.scorer import DetectionResult
from backend.detection.analysis.threat import (
    ThreatAnalysisResult,
    ThreatEvidence,
)


def _rule_ids(result: DetectionResult) -> frozenset[str]:
    """Return triggered rule IDs for efficient pattern matching."""

    return frozenset(reason.rule for reason in result.reasons)


def analyze_threats(
    result: DetectionResult,
) -> ThreatAnalysisResult:
    """Interpret detection reasons as higher-level threat evidence.

    This function is intentionally score-neutral. It does not modify
    DetectionResult and does not alter risk classification.
    """

    rule_ids = _rule_ids(result)
    evidence: list[ThreatEvidence] = []

    # ---------------------------------------------------------
    # Domain deception
    # ---------------------------------------------------------

    domain_deception_rules = (
        "BRAND_IMPERSONATION",
        "TYPOSQUATTING",
        "DECEPTIVE_DOMAIN_STRUCTURE",
    )

    matched_domain_rules = tuple(
        rule_id
        for rule_id in domain_deception_rules
        if rule_id in rule_ids
    )

    if matched_domain_rules:
        confidence = (
            0.95
            if len(matched_domain_rules) >= 2
            else 0.80
        )

        severity = (
            "HIGH"
            if len(matched_domain_rules) >= 2
            else "MEDIUM"
        )

        evidence.append(
            ThreatEvidence(
                category="DOMAIN_DECEPTION",
                severity=severity,
                confidence=confidence,
                rule_ids=matched_domain_rules,
                explanation=(
                    "The hostname contains evidence of brand "
                    "impersonation or deceptive domain structure."
                ),
            )
        )

    # ---------------------------------------------------------
    # Userinfo deception
    # ---------------------------------------------------------

    userinfo_rules = (
        "USERINFO_AT_SYMBOL",
        "DECEPTIVE_USERINFO_DESTINATION",
    )

    matched_userinfo_rules = tuple(
        rule_id
        for rule_id in userinfo_rules
        if rule_id in rule_ids
    )

    if matched_userinfo_rules:
        evidence.append(
            ThreatEvidence(
                category="USERINFO_DECEPTION",
                severity=(
                    "HIGH"
                    if "DECEPTIVE_USERINFO_DESTINATION" in rule_ids
                    else "MEDIUM"
                ),
                confidence=(
                    0.95
                    if "DECEPTIVE_USERINFO_DESTINATION" in rule_ids
                    else 0.75
                ),
                rule_ids=matched_userinfo_rules,
                explanation=(
                    "The URL uses authority userinfo in a way that "
                    "may obscure the actual destination hostname."
                ),
            )
        )

    # ---------------------------------------------------------
    # Redirect abuse
    # ---------------------------------------------------------

    redirect_rules = (
        "SUSPICIOUS_REDIRECT_PARAMETER",
        "EXTERNAL_REDIRECT_DESTINATION",
    )

    matched_redirect_rules = tuple(
        rule_id
        for rule_id in redirect_rules
        if rule_id in rule_ids
    )

    if matched_redirect_rules:
        evidence.append(
            ThreatEvidence(
                category="REDIRECT_ABUSE",
                severity="MEDIUM",
                confidence=0.75,
                rule_ids=matched_redirect_rules,
                explanation=(
                    "The URL contains redirect behavior that may "
                    "move the user to another destination."
                ),
            )
        )

    # ---------------------------------------------------------
    # URL obfuscation
    # ---------------------------------------------------------

    obfuscation_rules = (
        "SUSPICIOUS_URL_ENCODING",
        "PUNYCODE_HOSTNAME",
    )

    matched_obfuscation_rules = tuple(
        rule_id
        for rule_id in obfuscation_rules
        if rule_id in rule_ids
    )

    if matched_obfuscation_rules:
        evidence.append(
            ThreatEvidence(
                category="URL_OBFUSCATION",
                severity="MEDIUM",
                confidence=0.70,
                rule_ids=matched_obfuscation_rules,
                explanation=(
                    "The URL contains structural encoding or "
                    "internationalized hostname characteristics "
                    "that may obscure its meaning."
                ),
            )
        )

    # ---------------------------------------------------------
    # Path traversal
    # ---------------------------------------------------------

    if "ENCODED_PATH_TRAVERSAL" in rule_ids:
        evidence.append(
            ThreatEvidence(
                category="PATH_TRAVERSAL",
                severity="HIGH",
                confidence=0.90,
                rule_ids=(
                    "ENCODED_PATH_TRAVERSAL",
                ),
                explanation=(
                    "The URL contains encoded parent-directory "
                    "traversal sequences."
                ),
            )
        )

    # ---------------------------------------------------------
    # Network anomaly
    # ---------------------------------------------------------

    if "IP_ADDRESS_HOST" in rule_ids:
        evidence.append(
            ThreatEvidence(
                category="NETWORK_ANOMALY",
                severity="MEDIUM",
                confidence=0.80,
                rule_ids=(
                    "IP_ADDRESS_HOST",
                ),
                explanation=(
                    "The URL uses an IP address instead of a "
                    "conventional hostname."
                ),
            )
        )

    return ThreatAnalysisResult(
        evidence=tuple(evidence),
    )
