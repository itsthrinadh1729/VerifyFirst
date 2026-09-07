"""Heuristic detection rules for VerifyFirst."""

from dataclasses import dataclass
from typing import Callable
from backend.detection.features.extractor import URLFeatures
from backend.detection.features.brands import (
    check_brand_impersonation,
    check_typosquatting,
)


@dataclass(frozen=True)
class RuleResult:
    """Outcome of evaluating a single detection rule."""

    rule_id: str
    triggered: bool
    weight: int
    message: str


@dataclass(frozen=True)
class RuleDefinition:
    """Definition of a heuristic detection rule."""

    rule_id: str
    weight: int
    message: str
    evaluator: Callable[[URLFeatures], bool]

    def evaluate(self, features: URLFeatures) -> RuleResult:
        triggered = bool(self.evaluator(features))
        return RuleResult(
            rule_id=self.rule_id,
            triggered=triggered,
            weight=self.weight if triggered else 0,
            message=self.message if triggered else "",
        )


# ── Existing baseline rules (Phase 5 — unchanged) ──

RULES: list[RuleDefinition] = [
    RuleDefinition(
        rule_id="IP_ADDRESS_HOST",
        weight=40,
        message="The website uses an IP address directly instead of a conventional domain name.",
        evaluator=lambda f: f.is_ip_address,
    ),
    RuleDefinition(
        rule_id="USERINFO_AT_SYMBOL",
        weight=25,
        message="The URL contains an '@' character, which can obscure the true destination host.",
        evaluator=lambda f: f.has_at_symbol,
    ),
    RuleDefinition(
        rule_id="EXCESSIVE_SUBDOMAINS",
        weight=20,
        message="The website uses an unusually deep subdomain hierarchy.",
        evaluator=lambda f: f.num_subdomains >= 4,
    ),
    RuleDefinition(
        rule_id="EXCESSIVE_URL_LENGTH",
        weight=10,
        message="The URL is unusually long (>200 characters).",
        evaluator=lambda f: f.url_length > 200,
    ),
    RuleDefinition(
        rule_id="EXCESSIVE_HOST_HYPHENS",
        weight=10,
        message="The domain name contains multiple hyphens.",
        evaluator=lambda f: f.num_hyphens_host >= 3,
    ),

    # ── Phase 5A: New detection rules ──

    RuleDefinition(
        rule_id="BRAND_IMPERSONATION",
        weight=35,
        message="The hostname contains a well-known brand name but uses a non-legitimate domain.",
        evaluator=lambda f: check_brand_impersonation(f.hostname_tokens, f.registered_domain) is not None,
    ),
    RuleDefinition(
        rule_id="TYPOSQUATTING",
        weight=30,
        message="The hostname closely resembles a well-known brand, which may indicate typosquatting.",
        evaluator=lambda f: check_typosquatting(f.hostname_tokens, f.registered_domain) is not None,
    ),
    RuleDefinition(
        rule_id="PUNYCODE_HOSTNAME",
        weight=20,
        message="The hostname uses internationalized characters (Punycode) which may require additional scrutiny.",
        evaluator=lambda f: f.is_punycode,
    ),
    RuleDefinition(
        rule_id="SUSPICIOUS_URL_ENCODING",
        weight=15,
        message="The URL contains unusual encoding in its structure that may obscure the actual destination.",
        evaluator=lambda f: f.has_suspicious_encoding,
    ),
]


def evaluate_rules(features: URLFeatures) -> list[RuleResult]:
    """Evaluate all configured rules against extracted URL features."""
    return [rule.evaluate(features) for rule in RULES]
