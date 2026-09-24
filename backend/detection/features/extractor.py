"""Deterministic URL feature extraction for VerifyFirst."""

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote, urlsplit


@dataclass(frozen=True)
class URLFeatures:
    """Deterministic structural features extracted from a URL."""

    # ── Existing baseline features ──
    host: str
    is_ip_address: bool
    url_length: int
    host_length: int
    num_subdomains: int
    num_hyphens_host: int
    has_at_symbol: bool
    num_dots_host: int

    # ── Existing Phase 5A features ──
    is_punycode: bool
    has_suspicious_encoding: bool
    registered_domain: str
    hostname_tokens: list[str]

    # ── Module 1: advanced structural features ──
    is_ipv4_address: bool = False
    is_ipv6_address: bool = False
    normalized_host: str = ""
    subdomain_depth: int = 0
    port: int | None = None
    is_non_standard_port: bool = False
    path_depth: int = 0
    query_parameter_names: tuple[str, ...] = ()
    has_suspicious_redirect_parameter: bool = False
    has_fragment: bool = False
    hostname_labels: tuple[str, ...] = ()
    redirect_parameter_names: tuple[str, ...] = ()
    has_external_redirect_destination: bool = False
    redirect_destinations: tuple[str, ...] = ()
    has_userinfo: bool = False
    userinfo_length: int = 0
    hostname_label_count: int = 0
    longest_hostname_label_length: int = 0
    numeric_hostname_label_count: int = 0
    mixed_alphanumeric_label_count: int = 0
    userinfo_host_hint: str | None = None
    has_deceptive_userinfo_destination: bool = False
    has_encoded_path_traversal: bool = False
    has_mixed_unicode_scripts: bool = False


def _has_mixed_unicode_scripts(hostname: str | None) -> bool:
    """Detect multiple basic Unicode script ranges in a hostname."""

    if not hostname:
        return False

    has_latin = False
    has_cyrillic = False
    has_greek = False

    for char in hostname:
        codepoint = ord(char)

        if (
            0x0041 <= codepoint <= 0x005A
            or 0x0061 <= codepoint <= 0x007A
        ):
            has_latin = True

        elif 0x0400 <= codepoint <= 0x04FF:
            has_cyrillic = True

        elif 0x0370 <= codepoint <= 0x03FF:
            has_greek = True

    return sum(
        [
            has_latin,
            has_cyrillic,
            has_greek,
        ]
    ) > 1


def _normalize_ipv4(hostname: str) -> str | None:
    """Normalize alternate IPv4 formats to dotted-decimal notation."""
    if not hostname:
        return None

    parts = hostname.split(".")

    if len(parts) > 4:
        return None

    # Avoid interpreting arbitrary small decimal hostnames as IPv4.
    if len(parts) == 1 and hostname.isdigit() and not hostname.startswith("0"):
        if int(hostname) < 16777216:
            return None

    numbers = []

    for part in parts:
        if not part:
            return None

        part_lower = part.lower()

        try:
            if part_lower.startswith("0x"):
                numbers.append(int(part_lower, 16))
            elif part_lower.startswith("0") and len(part_lower) > 1:
                numbers.append(int(part_lower, 8))
            else:
                if not part_lower.isdigit():
                    return None

                numbers.append(int(part_lower, 10))

        except ValueError:
            return None

    if not numbers:
        return None

    last = numbers.pop()

    if last >= (256 ** (4 - len(numbers))):
        return None

    for number in numbers:
        if number > 255:
            return None

    while len(numbers) < 4:
        numbers.append(
            (last >> (8 * (3 - len(numbers)))) & 0xFF
        )

    return (
        f"{numbers[0]}."
        f"{numbers[1]}."
        f"{numbers[2]}."
        f"{numbers[3]}"
    )


def _is_ipv4(hostname: str) -> bool:
    """Return True when hostname represents an IPv4 address."""
    if not hostname:
        return False

    clean_host = hostname.strip("[]")

    try:
        address = ipaddress.ip_address(clean_host)
        return address.version == 4
    except ValueError:
        pass

    normalized = _normalize_ipv4(clean_host)

    if normalized:
        try:
            address = ipaddress.ip_address(normalized)
            return address.version == 4
        except ValueError:
            pass

    return False


def _is_ipv6(hostname: str) -> bool:
    """Return True when hostname represents an IPv6 address."""
    if not hostname:
        return False

    clean_host = hostname.strip("[]")

    try:
        address = ipaddress.ip_address(clean_host)
        return address.version == 6
    except ValueError:
        return False


def _is_ip(hostname: str) -> bool:
    """Return True when hostname is IPv4 or IPv6."""
    return _is_ipv4(hostname) or _is_ipv6(hostname)


def _normalize_hostname(hostname: str) -> str:
    """Return a canonical hostname representation for analysis.

    The original URL is never modified. This normalized hostname is
    used only for deterministic structural analysis.
    """
    if not hostname:
        return ""

    normalized = hostname.strip().lower()

    # DNS fully-qualified hostnames may legally end in a root-label dot.
    # It is not useful as a separate structural hostname component.
    normalized = normalized.rstrip(".")

    return normalized


def _count_subdomains(hostname: str, is_ip: bool) -> int:
    """Calculate subdomain count excluding registered domain."""
    if is_ip or not hostname:
        return 0

    parts = [part for part in hostname.split(".") if part]

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


_TWO_PART_TLDS = frozenset({
    "co.uk",
    "co.in",
    "co.jp",
    "co.kr",
    "co.nz",
    "co.za",
    "com.au",
    "com.br",
    "com.cn",
    "com.mx",
    "com.sg",
    "com.tw",
    "org.uk",
    "org.au",
    "net.au",
    "ac.uk",
    "gov.uk",
})


def _extract_registered_domain(hostname: str, is_ip: bool) -> str:
    """Extract the effective registered domain."""
    if is_ip or not hostname:
        return hostname

    parts = [part for part in hostname.split(".") if part]

    if len(parts) <= 2:
        return hostname

    last_two = ".".join(parts[-2:])

    if last_two in _TWO_PART_TLDS:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def _is_punycode(hostname: str) -> bool:
    """Check whether any hostname label uses Punycode."""
    if not hostname:
        return False

    return any(
        label.lower().startswith("xn--")
        for label in hostname.split(".")
    )


_PERCENT_ENCODED_RE = re.compile(r"%[0-9A-Fa-f]{2}")

_NORMAL_ENCODED_CHARS = frozenset({
    "%20",
    "%2f",
    "%2F",
    "%3d",
    "%3D",
    "%26",
    "%2b",
    "%2B",
    "%3f",
    "%3F",
    "%23",
    "%3a",
    "%3A",
    "%2c",
    "%2C",
})


def _has_suspicious_encoding(url: str) -> bool:
    """Detect excessive or unusual structural percent encoding."""
    parsed = urlsplit(url)

    structural_part = (
        f"{parsed.scheme}://"
        f"{parsed.netloc}"
        f"{parsed.path}"
    )

    matches = _PERCENT_ENCODED_RE.findall(structural_part)

    if not matches:
        return False

    normal_encoded = {
        value.lower()
        for value in _NORMAL_ENCODED_CHARS
    }

    unusual_count = sum(
        1
        for match in matches
        if match.lower() not in normal_encoded
    )

    return unusual_count > 3


def _tokenize_hostname(hostname: str) -> list[str]:
    """Split hostname into lowercase tokens by dots and hyphens."""
    if not hostname:
        return []

    tokens: list[str] = []

    for label in hostname.split("."):
        for part in label.split("-"):
            if part:
                tokens.append(part.lower())

    return tokens


def _get_subdomain_depth(
    hostname: str,
    registered_domain: str,
    is_ip: bool,
) -> int:
    """Return the number of labels preceding the registered domain."""
    if is_ip or not hostname or not registered_domain:
        return 0

    if hostname == registered_domain:
        return 0

    prefix = hostname.removesuffix(
        "." + registered_domain
    )

    if not prefix:
        return 0

    return len(
        [part for part in prefix.split(".") if part]
    )


def _get_port(parsed) -> int | None:
    """Safely obtain the explicit URL port."""
    try:
        return parsed.port
    except ValueError:
        # Malformed/out-of-range ports are intentionally not converted
        # into a numeric feature.
        return None


def _is_non_standard_port(parsed, port: int | None) -> bool:
    """Identify explicit non-standard HTTP/HTTPS ports."""
    if port is None:
        return False

    scheme = parsed.scheme.lower()

    if scheme == "http":
        return port != 80

    if scheme == "https":
        return port != 443

    return True


def _get_path_depth(path: str) -> int:
    """Count meaningful path segments."""
    if not path or path == "/":
        return 0

    return len([
        segment
        for segment in path.split("/")
        if segment
    ])


_REDIRECT_PARAMETER_NAMES = frozenset({
    "redirect",
    "redirect_uri",
    "redirect_url",
    "url",
    "next",
    "continue",
    "return",
    "returnurl",
    "return_url",
    "dest",
    "destination",
    "target",
})


def _get_query_parameter_names(url: str) -> tuple[str, ...]:
    """Extract normalized query parameter names."""
    parsed = urlsplit(url)

    if not parsed.query:
        return ()

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    names = {
        name.strip().lower()
        for name, _ in parameters
        if name.strip()
    }

    return tuple(sorted(names))


def _has_suspicious_redirect_parameter(
    parameter_names: tuple[str, ...],
) -> bool:
    """Detect URL parameters commonly used for redirection."""
    return any(
        parameter in _REDIRECT_PARAMETER_NAMES
        for parameter in parameter_names
    )


def _analyze_redirect_destinations(
    url: str,
) -> tuple[tuple[str, ...], bool]:
    """Analyze redirect-related query parameters.

    Returns:
        (redirect_destinations, has_external_destination)

    Only redirect-related parameters are inspected.
    """
    parsed = urlsplit(url)

    if not parsed.query:
        return (), False

    source_scheme = parsed.scheme.lower()
    source_host = (parsed.hostname or "").lower()

    if not source_scheme or not source_host:
        return (), False

    destinations: list[str] = []

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    for name, value in parameters:
        normalized_name = name.strip().lower()

        if normalized_name not in _REDIRECT_PARAMETER_NAMES:
            continue

        if not value:
            continue

        decoded_value = unquote(value).strip()

        if not decoded_value:
            continue

        destination = urlsplit(decoded_value)

        # Relative destinations are not external.
        if not destination.scheme and not destination.netloc:
            continue

        normalized_source_host = source_host.rstrip(".")

        if destination.netloc and not destination.scheme:
            destination_host = (
                destination.hostname or ""
            ).lower().rstrip(".")

            if destination_host:
                if destination_host != normalized_source_host:
                    destinations.append(decoded_value)

            continue

        destination_scheme = destination.scheme.lower()

        # Only HTTP(S) destinations are considered external web
        # destinations here.
        if destination_scheme not in {"http", "https"}:
            continue

        destination_host = (
            destination.hostname or ""
        ).lower().rstrip(".")

        if not destination_host:
            continue

        if (
            destination_scheme == source_scheme
            and destination_host == normalized_source_host
        ):
            continue

        destinations.append(decoded_value)

    return (
        tuple(destinations),
        bool(destinations),
    )


def _analyze_hostname_labels(
    hostname_labels: tuple[str, ...],
) -> tuple[int, int, int, int]:
    """
    Analyze hostname label structure.

    Returns:
        (
            hostname_label_count,
            longest_hostname_label_length,
            numeric_hostname_label_count,
            mixed_alphanumeric_label_count,
        )
    """
    if not hostname_labels:
        return 0, 0, 0, 0

    hostname_label_count = len(hostname_labels)

    longest_hostname_label_length = max(
        len(label) for label in hostname_labels
    )

    numeric_hostname_label_count = sum(
        1 for label in hostname_labels if label.isdigit()
    )

    mixed_alphanumeric_label_count = sum(
        1
        for label in hostname_labels
        if any(char.isalpha() for char in label)
        and any(char.isdigit() for char in label)
    )

    return (
        hostname_label_count,
        longest_hostname_label_length,
        numeric_hostname_label_count,
        mixed_alphanumeric_label_count,
    )


def _analyze_userinfo(
    parsed_url,
) -> tuple[bool, int, str | None]:
    """Analyze authority userinfo and return a host-like userinfo hint."""

    netloc = parsed_url.netloc

    if "@" not in netloc:
        return False, 0, None

    userinfo = netloc.rsplit("@", 1)[0]

    if not userinfo:
        return True, 0, None

    # Userinfo may technically contain username:password.
    username = userinfo.rsplit(":", 1)[0]

    return True, len(userinfo), username


def _has_deceptive_userinfo_destination(
    userinfo_host_hint: str | None,
    hostname: str | None,
) -> bool:
    """Detect a domain-like userinfo hint that differs from the actual host."""

    if not userinfo_host_hint or not hostname:
        return False

    hint = userinfo_host_hint.lower().rstrip(".")
    actual_host = hostname.lower().rstrip(".")

    # Only evaluate domain-like userinfo values.
    if "." not in hint:
        return False

    return hint != actual_host


def _has_encoded_path_traversal(url: str) -> bool:
    """Detect encoded parent-directory traversal in the URL path."""

    parsed = urlsplit(url)

    if not parsed.path:
        return False

    decoded_path = unquote(parsed.path)

    return (
        "/../" in f"/{decoded_path.lstrip('/')}"
        or decoded_path.startswith("../")
        or decoded_path.endswith("/..")
        or decoded_path == ".."
    )


def extract_features(url: str) -> URLFeatures:
    """Extract deterministic structural features from a URL."""
    parsed = urlsplit(url)

    raw_host = parsed.hostname or ""
    normalized_host = _normalize_hostname(raw_host)

    hostname_labels = tuple(
        label
        for label in normalized_host.split(".")
        if label
    )

    is_ipv4 = _is_ipv4(normalized_host)
    is_ipv6 = _is_ipv6(normalized_host)
    is_ip = is_ipv4 or is_ipv6

    registered_domain = _extract_registered_domain(
        normalized_host,
        is_ip,
    )

    subdomain_depth = _get_subdomain_depth(
        normalized_host,
        registered_domain,
        is_ip,
    )

    parameter_names = _get_query_parameter_names(url)

    redirect_destinations, has_external_redirect = (
        _analyze_redirect_destinations(url)
    )

    port = _get_port(parsed)

    has_userinfo, userinfo_length, userinfo_host_hint = _analyze_userinfo(parsed)

    has_deceptive_userinfo_destination = _has_deceptive_userinfo_destination(
        userinfo_host_hint,
        parsed.hostname,
    )

    has_encoded_path_traversal = _has_encoded_path_traversal(url)

    has_mixed_unicode_scripts = _has_mixed_unicode_scripts(parsed.hostname)

    (
        hostname_label_count,
        longest_hostname_label_length,
        numeric_hostname_label_count,
        mixed_alphanumeric_label_count,
    ) = _analyze_hostname_labels(hostname_labels)

    return URLFeatures(
        # Existing features
        host=normalized_host,
        is_ip_address=is_ip,
        url_length=len(url),
        host_length=len(normalized_host),
        num_subdomains=_count_subdomains(
            normalized_host,
            is_ip,
        ),
        num_hyphens_host=normalized_host.count("-"),
        has_at_symbol="@" in (parsed.netloc or ""),
        num_dots_host=normalized_host.count("."),

        # Existing Phase 5A features
        is_punycode=_is_punycode(normalized_host),
        has_suspicious_encoding=_has_suspicious_encoding(url),
        registered_domain=registered_domain,
        hostname_tokens=_tokenize_hostname(normalized_host),

        # Module 1 features
        is_ipv4_address=is_ipv4,
        is_ipv6_address=is_ipv6,
        normalized_host=normalized_host,
        subdomain_depth=subdomain_depth,
        port=port,
        is_non_standard_port=_is_non_standard_port(
            parsed,
            port,
        ),
        path_depth=_get_path_depth(parsed.path),
        query_parameter_names=parameter_names,
        has_suspicious_redirect_parameter=(
            _has_suspicious_redirect_parameter(
                parameter_names
            )
        ),
        has_fragment=bool(parsed.fragment),
        hostname_labels=hostname_labels,
        redirect_parameter_names=tuple(
            name
            for name in parameter_names
            if name in _REDIRECT_PARAMETER_NAMES
        ),
        has_external_redirect_destination=has_external_redirect,
        redirect_destinations=redirect_destinations,
        has_userinfo=has_userinfo,
        userinfo_length=userinfo_length,
        hostname_label_count=hostname_label_count,
        longest_hostname_label_length=longest_hostname_label_length,
        numeric_hostname_label_count=numeric_hostname_label_count,
        mixed_alphanumeric_label_count=mixed_alphanumeric_label_count,
        userinfo_host_hint=userinfo_host_hint,
        has_deceptive_userinfo_destination=has_deceptive_userinfo_destination,
        has_encoded_path_traversal=has_encoded_path_traversal,
        has_mixed_unicode_scripts=has_mixed_unicode_scripts,
    )
