"""Deterministic URL feature extraction."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


@dataclass(frozen=True)
class URLFeatures:
    """12 core structural features extracted deterministically from a URL."""

    # ── Original 8 features (unchanged) ──
    host: str
    is_ip_address: bool
    url_length: int
    host_length: int
    num_subdomains: int
    num_hyphens_host: int
    has_at_symbol: bool
    num_dots_host: int

    # ── Phase 5A: 4 new features ──
    is_punycode: bool
    has_suspicious_encoding: bool
    registered_domain: str
    hostname_tokens: list[str]


def _is_ip(hostname: str) -> bool:
    """Check whether a given hostname string is an IPv4 or IPv6 address."""
    clean_host = hostname.strip("[]")
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        return False


def _count_subdomains(hostname: str, is_ip: bool) -> int:
    """Calculate the number of subdomain labels excluding domain name and TLD."""
    if is_ip or not hostname:
        return 0

    parts = [p for p in hostname.split(".") if p]
    # For a typical domain e.g. "sub.example.com" -> parts = 3, subdomains = 1
    # For "a.b.c.d.example.com" -> parts = 6, subdomains = 4
    if len(parts) <= 2:
        return 0
    return len(parts) - 2


# Known two-part TLD suffixes where the registered domain includes 3 labels.
_TWO_PART_TLDS = frozenset({
    "co.uk", "co.in", "co.jp", "co.kr", "co.nz", "co.za",
    "com.au", "com.br", "com.cn", "com.mx", "com.sg", "com.tw",
    "org.uk", "org.au", "net.au", "ac.uk", "gov.uk",
})


def _extract_registered_domain(hostname: str, is_ip: bool) -> str:
    """Extract the effective registered domain from a hostname.

    For "sub.example.com" returns "example.com".
    For "sub.example.co.uk" returns "example.co.uk".
    For IP addresses, returns the IP itself.
    """
    if is_ip or not hostname:
        return hostname

    parts = [p for p in hostname.split(".") if p]
    if len(parts) <= 2:
        return hostname

    # Check if the last two parts form a known two-part TLD
    last_two = ".".join(parts[-2:])
    if last_two in _TWO_PART_TLDS and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def _is_punycode(hostname: str) -> bool:
    """Check if any label in the hostname uses Punycode (IDN) encoding."""
    if not hostname:
        return False
    for label in hostname.split("."):
        if label.lower().startswith("xn--"):
            return True
    return False


# Pattern matching percent-encoded characters (%XX).
_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

# Standard safe percent-encoded characters that appear in normal URLs.
# Space (%20), slash (%2F), equals (%3D), ampersand (%26), plus (%2B),
# question mark (%3F), hash (%23), colon (%3A), comma (%2C).
_NORMAL_ENCODED_CHARS = frozenset({
    "%20", "%2f", "%2F", "%3d", "%3D", "%26", "%2b", "%2B",
    "%3f", "%3F", "%23", "%3a", "%3A", "%2c", "%2C",
})


def _has_suspicious_encoding(url: str) -> bool:
    """Detect excessive or unusual percent-encoding that may obscure URL structure.

    Conservative implementation:
    - Only flags encoding that is NOT standard query-parameter encoding.
    - Ignores normal encoded characters (%20 space, %2F slash, etc.).
    - Focuses on encoding in the hostname and path portions.
    - Requires >3 unusual encoded characters to trigger.
    """
    parsed = urlsplit(url)
    # Focus on scheme + authority + path (exclude query and fragment
    # where percent-encoding is normal and expected)
    structural_part = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

    matches = _PERCENT_ENCODED_RE.findall(structural_part)
    if not matches:
        return False

    unusual_count = sum(
        1 for m in matches if m.lower() not in {s.lower() for s in _NORMAL_ENCODED_CHARS}
    )
    return unusual_count > 3


def _tokenize_hostname(hostname: str) -> list[str]:
    """Split hostname into tokens by '.' and '-' for brand matching.

    Only produces tokens from the hostname itself, never from the URL path.
    """
    if not hostname:
        return []
    # Split on dots first, then split each label on hyphens
    tokens: list[str] = []
    for label in hostname.split("."):
        for part in label.split("-"):
            if part:
                tokens.append(part.lower())
    return tokens


def extract_features(url: str) -> URLFeatures:
    """Extract the 12 approved structural features from a validated URL."""
    parsed = urlsplit(url)
    host = (parsed.hostname or "").lower()
    is_ip = _is_ip(host)

    return URLFeatures(
        host=host,
        is_ip_address=is_ip,
        url_length=len(url),
        host_length=len(host),
        num_subdomains=_count_subdomains(host, is_ip),
        num_hyphens_host=host.count("-"),
        has_at_symbol="@" in url,
        num_dots_host=host.count("."),
        # Phase 5A new features
        is_punycode=_is_punycode(host),
        has_suspicious_encoding=_has_suspicious_encoding(url),
        registered_domain=_extract_registered_domain(host, is_ip),
        hostname_tokens=_tokenize_hostname(host),
    )
