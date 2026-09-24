"""Threat Context & Explanation generation."""

from dataclasses import dataclass

from backend.detection.analysis.severity import ThreatAssessment
from backend.detection.analysis.threat import ThreatAnalysisResult


@dataclass(frozen=True)
class ThreatContext:
    title: str
    summary: str
    technical_details: tuple[str, ...]
    user_impact: str
    recommended_action: str


PATTERN_CONTEXT = {
    "DOMAIN_IMPERSONATION": {
        "title": "Domain impersonation detected",
        "summary": (
            "The URL contains domain characteristics associated "
            "with impersonation of a trusted brand."
        ),
        "user_impact": (
            "The website may be attempting to imitate a trusted "
            "service and could be used to collect sensitive information."
        ),
        "recommended_action": (
            "Verify the domain carefully before entering credentials "
            "or other sensitive information."
        ),
    },
    "CREDENTIAL_PHISHING": {
        "title": "Possible credential phishing",
        "summary": (
            "The URL combines indicators associated with a "
            "credential-harvesting attempt."
        ),
        "user_impact": (
            "The page may attempt to obtain usernames, passwords, "
            "or other authentication information."
        ),
        "recommended_action": (
            "Do not enter credentials unless the destination has "
            "been independently verified."
        ),
    },
    "USERINFO_DECEPTION": {
        "title": "Deceptive URL structure detected",
        "summary": (
            "The URL uses the user-information portion of the URL "
            "in a way that may make the destination appear trustworthy."
        ),
        "user_impact": (
            "The visible portion of the URL may cause the user to "
            "mistake the trusted-looking text for the actual destination."
        ),
        "recommended_action": (
            "Check the actual hostname before opening or entering "
            "sensitive information."
        ),
    },
    "PATH_MANIPULATION": {
        "title": "Suspicious path manipulation detected",
        "summary": (
            "The URL contains encoded path traversal characteristics."
        ),
        "user_impact": (
            "Encoded path manipulation can be used to obscure "
            "the actual resource being requested."
        ),
        "recommended_action": (
            "Avoid interacting with the destination unless it is "
            "known and trusted."
        ),
    },
    "URL_OBFUSCATION": {
        "title": "URL obfuscation detected",
        "summary": (
            "The URL contains multiple characteristics that can "
            "make its destination or structure harder to interpret."
        ),
        "user_impact": (
            "Obfuscated URLs can make malicious destinations harder "
            "for users to recognize."
        ),
        "recommended_action": (
            "Verify the complete destination before continuing."
        ),
    },
    "REDIRECT_ABUSE": {
        "title": "Suspicious redirect detected",
        "summary": (
            "The URL contains redirect-related characteristics "
            "that may obscure the eventual destination."
        ),
        "user_impact": (
            "Redirect chains can send users to destinations different "
            "from the initial URL."
        ),
        "recommended_action": (
            "Verify the final destination before continuing."
        ),
    },
    "IDN_DECEPTION": {
        "title": "Internationalized domain detected",
        "summary": (
            "The domain uses internationalized or encoded hostname "
            "characteristics that may make visual identification harder."
        ),
        "user_impact": (
            "Visually similar characters can sometimes be used to "
            "make an untrusted domain resemble a trusted one."
        ),
        "recommended_action": (
            "Verify the domain carefully before entering sensitive information."
        ),
    },
}


SEVERITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _select_primary_pattern(analysis: ThreatAnalysisResult):
    if not analysis.patterns:
        return None

    return max(
        analysis.patterns,
        key=lambda pattern: (
            SEVERITY_RANK[pattern.severity],
            pattern.confidence,
        ),
    )


def _build_technical_details(
    analysis: ThreatAnalysisResult,
) -> tuple[str, ...]:
    details: list[str] = []

    for evidence in analysis.evidence:
        for rule_id in evidence.rule_ids:
            details.append(
                f"{rule_id}: {evidence.explanation}"
            )

    return tuple(dict.fromkeys(details))


def build_threat_context(
    analysis: ThreatAnalysisResult,
    assessment: ThreatAssessment,
) -> ThreatContext | None:
    if not analysis.evidence and not analysis.patterns:
        return None

    primary_pattern = _select_primary_pattern(analysis)

    if primary_pattern is not None:
        pattern_context = PATTERN_CONTEXT.get(
            primary_pattern.pattern_id
        )
    else:
        pattern_context = None

    if pattern_context is None:
        title = "Suspicious URL characteristics detected"
        summary = (
            "The URL contains characteristics associated "
            "with potentially unsafe behavior."
        )
        user_impact = (
            "These characteristics may increase the risk of "
            "interacting with the destination."
        )
        recommended_action = (
            "Verify the destination before continuing."
        )
    else:
        title = pattern_context["title"]
        summary = pattern_context["summary"]
        user_impact = pattern_context["user_impact"]
        recommended_action = pattern_context["recommended_action"]

    return ThreatContext(
        title=title,
        summary=summary,
        technical_details=_build_technical_details(analysis),
        user_impact=user_impact,
        recommended_action=recommended_action,
    )
