"""Brand impersonation and typosquatting detection for VerifyFirst.

Provides a curated brand list and pure detection functions used by the
detection rules. No external dependencies — uses only Python stdlib.
"""

import difflib
from dataclasses import dataclass

# Minimum token length to consider for typosquatting comparison.
# Avoids false positives on short generic tokens like "app", "pay", "net".
MIN_TOKEN_LENGTH_FOR_TYPOSQUAT = 4

# Similarity ratio threshold for typosquatting detection (0.0–1.0).
# Initial experimental value — validated against known phishing patterns
# and legitimate domains. Subject to tuning after broader testing.
TYPOSQUAT_SIMILARITY_THRESHOLD = 0.75


@dataclass(frozen=True)
class BrandEntry:
    """A known brand with its legitimate registered domains."""

    name: str
    legitimate_domains: tuple[str, ...]


@dataclass(frozen=True)
class BrandMatch:
    """Result of a brand impersonation or typosquatting match."""

    brand_name: str
    matched_token: str
    similarity: float  # 1.0 for exact match, <1.0 for typosquat


# Curated high-value phishing targets.
# Each brand's legitimate_domains list contains the registered domains
# (not subdomains) that are genuinely operated by that brand.
BRANDS: tuple[BrandEntry, ...] = (
    BrandEntry("paypal", ("paypal.com",)),
    BrandEntry("apple", ("apple.com", "icloud.com")),
    BrandEntry("microsoft", ("microsoft.com", "live.com", "outlook.com", "office.com")),
    BrandEntry("google", ("google.com", "gmail.com", "youtube.com")),
    BrandEntry("amazon", ("amazon.com", "amazon.co.uk", "amazon.de", "amazon.in")),
    BrandEntry("netflix", ("netflix.com",)),
    BrandEntry("facebook", ("facebook.com", "fb.com")),
    BrandEntry("instagram", ("instagram.com",)),
    BrandEntry("whatsapp", ("whatsapp.com",)),
    BrandEntry("twitter", ("twitter.com", "x.com")),
    BrandEntry("linkedin", ("linkedin.com",)),
    BrandEntry("dropbox", ("dropbox.com",)),
    BrandEntry("chase", ("chase.com",)),
    BrandEntry("wellsfargo", ("wellsfargo.com",)),
    BrandEntry("bankofamerica", ("bankofamerica.com",)),
    BrandEntry("citibank", ("citibank.com", "citi.com")),
    BrandEntry("coinbase", ("coinbase.com",)),
    BrandEntry("binance", ("binance.com",)),
    BrandEntry("steam", ("steampowered.com", "steamcommunity.com")),
    BrandEntry("ebay", ("ebay.com",)),
    BrandEntry("yahoo", ("yahoo.com",)),
    BrandEntry("adobe", ("adobe.com",)),
    BrandEntry("spotify", ("spotify.com",)),
    BrandEntry("zoom", ("zoom.us",)),
    BrandEntry("slack", ("slack.com",)),
    BrandEntry("github", ("github.com",)),
    BrandEntry("stripe", ("stripe.com",)),
    BrandEntry("docusign", ("docusign.com", "docusign.net")),
    BrandEntry("usps", ("usps.com",)),
    BrandEntry("fedex", ("fedex.com",)),
    BrandEntry("dhl", ("dhl.com",)),
)


def _is_legitimate_domain(registered_domain: str, brand: BrandEntry) -> bool:
    """Check if a registered domain belongs to a brand's legitimate domains."""
    rd = registered_domain.lower()
    return rd in brand.legitimate_domains


def check_brand_impersonation(
    hostname_tokens: list[str],
    registered_domain: str,
) -> BrandMatch | None:
    """Detect exact brand-name tokens in a hostname of a non-legitimate domain.

    Only examines hostname-derived tokens, NOT path or query components.
    Returns None if the domain is the brand's legitimate domain (no false positive).
    """
    if not hostname_tokens or not registered_domain:
        return None

    for brand in BRANDS:
        for token in hostname_tokens:
            if token.lower() == brand.name:
                # Brand token found — check if domain is legitimate
                if _is_legitimate_domain(registered_domain, brand):
                    return None  # Legitimate brand domain, not impersonation
                return BrandMatch(
                    brand_name=brand.name,
                    matched_token=token.lower(),
                    similarity=1.0,
                )
    return None


def check_typosquatting(
    hostname_tokens: list[str],
    registered_domain: str,
) -> BrandMatch | None:
    """Detect hostname tokens that closely resemble a known brand (but are not exact).

    Uses difflib.SequenceMatcher for deterministic string similarity.
    Only considers tokens of sufficient length to avoid short-word false positives.
    Returns None if the domain is the brand's legitimate domain.
    """
    if not hostname_tokens or not registered_domain:
        return None

    best_match: BrandMatch | None = None
    best_similarity = 0.0

    for brand in BRANDS:
        # Skip brands whose legitimate domain matches
        if _is_legitimate_domain(registered_domain, brand):
            return None

        for token in hostname_tokens:
            token_lower = token.lower()
            # Skip tokens that are too short
            if len(token_lower) < MIN_TOKEN_LENGTH_FOR_TYPOSQUAT:
                continue
            # Skip exact matches (handled by brand impersonation rule)
            if token_lower == brand.name:
                continue

            ratio = difflib.SequenceMatcher(None, token_lower, brand.name).ratio()
            if ratio >= TYPOSQUAT_SIMILARITY_THRESHOLD and ratio > best_similarity:
                best_similarity = ratio
                best_match = BrandMatch(
                    brand_name=brand.name,
                    matched_token=token_lower,
                    similarity=ratio,
                )

    return best_match
