"""Threat pattern correlation engine."""

from backend.detection.analysis.threat import (
    ThreatAnalysisResult,
    ThreatPattern,
)


def _rule_ids(
    analysis: ThreatAnalysisResult,
) -> frozenset[str]:
    """Collect all rule IDs represented by threat evidence."""

    return frozenset(
        rule_id
        for evidence in analysis.evidence
        for rule_id in evidence.rule_ids
    )


def correlate_patterns(
    analysis: ThreatAnalysisResult,
) -> ThreatAnalysisResult:
    """Correlate independent evidence into higher-level threat patterns.

    This function is score-neutral. It never modifies the risk score,
    classification, or existing detection reasons.
    """

    rule_ids = _rule_ids(analysis)
    patterns: list[ThreatPattern] = []

    # ---------------------------------------------------------
    # Credential phishing
    # ---------------------------------------------------------

    matched_credential_rules = tuple(
        rule_id
        for rule_id in (
            "BRAND_IMPERSONATION",
            "TYPOSQUATTING",
            "DECEPTIVE_DOMAIN_STRUCTURE",
            "DECEPTIVE_USERINFO_DESTINATION",
            "EXTERNAL_REDIRECT_DESTINATION",
        )
        if rule_id in rule_ids
    )

    has_brand_signal = bool(
        rule_ids
        & {
            "BRAND_IMPERSONATION",
            "TYPOSQUATTING",
            "DECEPTIVE_DOMAIN_STRUCTURE",
        }
    )

    has_destination_abuse = bool(
        rule_ids
        & {
            "DECEPTIVE_USERINFO_DESTINATION",
            "EXTERNAL_REDIRECT_DESTINATION",
        }
    )

    if has_brand_signal and has_destination_abuse:
        patterns.append(
            ThreatPattern(
                pattern_id="CREDENTIAL_PHISHING",
                severity="HIGH",
                confidence=0.90,
                categories=(
                    "DOMAIN_DECEPTION",
                    "REDIRECT_ABUSE",
                ),
                rule_ids=matched_credential_rules,
                explanation=(
                    "Brand or domain deception is combined with "
                    "destination-obscuring or external redirect "
                    "behavior, forming a potential credential-"
                    "phishing pattern."
                ),
            )
        )

    # ---------------------------------------------------------
    # Domain impersonation
    # ---------------------------------------------------------

    domain_rules = (
        "BRAND_IMPERSONATION",
        "TYPOSQUATTING",
        "DECEPTIVE_DOMAIN_STRUCTURE",
    )

    matched_domain_rules = tuple(
        rule_id
        for rule_id in domain_rules
        if rule_id in rule_ids
    )

    if len(matched_domain_rules) >= 2:
        patterns.append(
            ThreatPattern(
                pattern_id="DOMAIN_IMPERSONATION",
                severity="HIGH",
                confidence=0.95,
                categories=(
                    "DOMAIN_DECEPTION",
                ),
                rule_ids=matched_domain_rules,
                explanation=(
                    "Multiple independent domain signals indicate "
                    "an attempt to imitate a legitimate brand or "
                    "domain."
                ),
            )
        )

    # ---------------------------------------------------------
    # URL obfuscation
    # ---------------------------------------------------------

    obfuscation_rules = (
        "SUSPICIOUS_URL_ENCODING",
        "PUNYCODE_HOSTNAME",
        "USERINFO_AT_SYMBOL",
        "EXTERNAL_REDIRECT_DESTINATION",
    )

    matched_obfuscation_rules = tuple(
        rule_id
        for rule_id in obfuscation_rules
        if rule_id in rule_ids
    )

    if len(matched_obfuscation_rules) >= 2:
        patterns.append(
            ThreatPattern(
                pattern_id="URL_OBFUSCATION",
                severity="MEDIUM",
                confidence=0.85,
                categories=(
                    "URL_OBFUSCATION",
                ),
                rule_ids=matched_obfuscation_rules,
                explanation=(
                    "Multiple URL-structure signals indicate "
                    "attempts to obscure or manipulate how the "
                    "destination is represented."
                ),
            )
        )

    # ---------------------------------------------------------
    # Userinfo deception
    # ---------------------------------------------------------

    if {
        "USERINFO_AT_SYMBOL",
        "DECEPTIVE_USERINFO_DESTINATION",
    }.issubset(rule_ids):
        patterns.append(
            ThreatPattern(
                pattern_id="USERINFO_DECEPTION",
                severity="HIGH",
                confidence=0.95,
                categories=(
                    "USERINFO_DECEPTION",
                ),
                rule_ids=(
                    "USERINFO_AT_SYMBOL",
                    "DECEPTIVE_USERINFO_DESTINATION",
                ),
                explanation=(
                    "The URL uses domain-like userinfo before '@' "
                    "to make the apparent destination differ from "
                    "the actual hostname."
                ),
            )
        )

    # ---------------------------------------------------------
    # Path manipulation
    # ---------------------------------------------------------

    if "ENCODED_PATH_TRAVERSAL" in rule_ids:
        patterns.append(
            ThreatPattern(
                pattern_id="PATH_MANIPULATION",
                severity="HIGH",
                confidence=0.90,
                categories=(
                    "PATH_TRAVERSAL",
                ),
                rule_ids=(
                    "ENCODED_PATH_TRAVERSAL",
                ),
                explanation=(
                    "Encoded parent-directory traversal indicates "
                    "path manipulation within the URL."
                ),
            )
        )

    return ThreatAnalysisResult(
        evidence=analysis.evidence,
        patterns=tuple(patterns),
    )
