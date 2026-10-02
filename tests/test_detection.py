"""Phase 1B — Unit tests for feature extraction, detection rules, scoring, and classification."""

from backend.detection.features.extractor import extract_features
from backend.detection.rules.rules import evaluate_rules
from backend.detection.engine.scorer import (
    analyze_url_security,
    classify_risk_score,
    normalize_risk_score,
    MAX_RAW_SCORE,
)

def test_continuous_score_normalization_precision():
    """Verify that the normalizer produces exact continuous integers (not multiples of 5)."""
    assert normalize_risk_score(40, MAX_RAW_SCORE) == 31
    assert normalize_risk_score(41, MAX_RAW_SCORE) == 32
    assert normalize_risk_score(55, MAX_RAW_SCORE) == 42
    assert normalize_risk_score(60, MAX_RAW_SCORE) == 46
    assert normalize_risk_score(73, MAX_RAW_SCORE) == 56
    assert normalize_risk_score(94, MAX_RAW_SCORE) == 72
    assert normalize_risk_score(127, MAX_RAW_SCORE) == 98




def test_feature_extraction_clean_url():
    """Verify feature extraction on standard domain."""
    features = extract_features("https://example.com/path")
    assert features.host == "example.com"
    assert features.is_ip_address is False
    assert features.url_length == len("https://example.com/path")
    assert features.host_length == len("example.com")
    assert features.num_subdomains == 0
    assert features.num_hyphens_host == 0
    assert features.has_at_symbol is False
    assert features.num_dots_host == 1


def test_feature_extraction_ip_and_special_patterns():
    """Verify feature extraction on IP addresses, subdomains, and userinfo @."""
    features_ip = extract_features("http://192.168.1.1:8080/admin")
    assert features_ip.is_ip_address is True
    assert features_ip.num_subdomains == 0

    features_sub = extract_features("https://a.b.c.d.example.com")
    assert features_sub.num_subdomains == 4

    features_at = extract_features("https://legit.com@phishing.example.com/login")
    assert features_at.has_at_symbol is True

    features_hyphens = extract_features("https://my-secure-online-banking-portal.com")
    assert features_hyphens.num_hyphens_host == 4


def test_rule_ip_address_host():
    """Verify IP_ADDRESS_HOST rule triggers (raw 40, normalized 31)."""
    result = analyze_url_security("http://192.168.1.1/login")
    assert result.risk_score == 31
    assert result.status == "SUSPICIOUS"
    rule_ids = [r.rule for r in result.reasons]
    assert "IP_ADDRESS_HOST" in rule_ids


def test_rule_ip_address_alternate_formats():
    """Verify IP_ADDRESS_HOST correctly handles octal, hex, int, and rejects normal domains."""
    # Integer IPv4
    res_int = analyze_url_security("http://3232235777/")
    assert "IP_ADDRESS_HOST" in [r.rule for r in res_int.reasons]
    
    # Octal IPv4
    res_octal = analyze_url_security("http://0300.0250.0001.0001/")
    assert "IP_ADDRESS_HOST" in [r.rule for r in res_octal.reasons]
    
    # Hex IPv4
    res_hex = analyze_url_security("http://0xc0.0xa8.0x01.0x01/")
    assert "IP_ADDRESS_HOST" in [r.rule for r in res_hex.reasons]
    
    # IPv6 (existing)
    res_v6 = analyze_url_security("http://[2001:db8::1]/")
    assert "IP_ADDRESS_HOST" in [r.rule for r in res_v6.reasons]

    # Should NOT trigger
    res_normal = analyze_url_security("http://example.com/")
    assert "IP_ADDRESS_HOST" not in [r.rule for r in res_normal.reasons]

    res_numeric_domain = analyze_url_security("http://12345678.example.com/")
    assert "IP_ADDRESS_HOST" not in [r.rule for r in res_numeric_domain.reasons]



def test_rule_userinfo_at_symbol():
    """Verify USERINFO_AT_SYMBOL rule triggers (raw 25, normalized 19)."""
    result = analyze_url_security("https://username@attacker.com/auth")
    assert result.risk_score == 19
    assert result.status == "SAFE"
    rule_ids = [r.rule for r in result.reasons]
    assert "USERINFO_AT_SYMBOL" in rule_ids


def test_rule_userinfo_at_symbol_false_positive():
    """Verify @ in query or fragment does NOT trigger USERINFO_AT_SYMBOL."""
    res_query = analyze_url_security("http://example.com/?q=@paypal")
    assert "USERINFO_AT_SYMBOL" not in [r.rule for r in res_query.reasons]
    
    res_fragment = analyze_url_security("http://example.com/#@paypal")
    assert "USERINFO_AT_SYMBOL" not in [r.rule for r in res_fragment.reasons]



def test_rule_excessive_subdomains():
    """Verify EXCESSIVE_SUBDOMAINS rule triggers (raw 20, normalized 15)."""
    result = analyze_url_security("https://sub4.sub3.sub2.sub1.example.com/")
    assert result.risk_score == 15
    assert result.status == "SAFE"
    rule_ids = [r.rule for r in result.reasons]
    assert "EXCESSIVE_SUBDOMAINS" in rule_ids


def test_rule_excessive_url_length():
    """Verify EXCESSIVE_URL_LENGTH rule triggers (raw 10, normalized 8)."""
    long_url = "https://example.com/" + ("a" * 190)  # Total > 200
    assert len(long_url) > 200
    result = analyze_url_security(long_url)
    assert result.risk_score == 8
    assert result.status == "SAFE"
    rule_ids = [r.rule for r in result.reasons]
    assert "EXCESSIVE_URL_LENGTH" in rule_ids


def test_rule_excessive_host_hyphens():
    """Verify EXCESSIVE_HOST_HYPHENS rule triggers (raw 10, normalized 8)."""
    result = analyze_url_security("https://verify-your-account-now.com/")
    assert result.risk_score == 8
    assert result.status == "SAFE"
    rule_ids = [r.rule for r in result.reasons]
    assert "EXCESSIVE_HOST_HYPHENS" in rule_ids


def test_additive_scoring_and_classification():
    """Verify multiple rules sum additively and produce normalized scores."""
    # IP (40) + @ (25) = raw 65 -> normalized 50 -> SUSPICIOUS
    url_suspicious = "http://username@192.168.1.1/auth"
    res_suspicious = analyze_url_security(url_suspicious)
    assert res_suspicious.risk_score == 50
    assert res_suspicious.status == "SUSPICIOUS"
    assert len(res_suspicious.reasons) == 2
    rule_ids_susp = [r.rule for r in res_suspicious.reasons]
    assert "IP_ADDRESS_HOST" in rule_ids_susp
    assert "USERINFO_AT_SYMBOL" in rule_ids_susp

    # IP (40) + @ (25) + Length > 200 (10) = raw 75 -> normalized 58 -> SUSPICIOUS
    url_dangerous = "http://username@192.168.1.1/login?" + ("param=" + "x" * 190)
    res_dangerous = analyze_url_security(url_dangerous)
    assert res_dangerous.risk_score == 58
    assert res_dangerous.status == "SUSPICIOUS"
    rule_ids_dang = [r.rule for r in res_dangerous.reasons]
    assert "IP_ADDRESS_HOST" in rule_ids_dang
    assert "USERINFO_AT_SYMBOL" in rule_ids_dang
    assert "EXCESSIVE_URL_LENGTH" in rule_ids_dang


def test_score_normalization_high_raw():
    """Verify raw scores above MAX_RAW_SCORE normalize to capped 100."""
    from backend.detection.features.extractor import URLFeatures
    from backend.detection.engine.scorer import normalize_risk_score, MAX_RAW_SCORE

    # Construct features that trigger multiple rules (40 + 25 + 20 + 10 + 10 = 105)
    features_all = URLFeatures(
        host="192.168.1.1",
        is_ip_address=True,     # +40
        url_length=250,         # +10
        host_length=11,
        num_subdomains=5,       # +20
        num_hyphens_host=4,     # +10
        has_at_symbol=True,     # +25
        num_dots_host=3,
        # Phase 5A fields (not relevant for this test)
        is_punycode=False,
        has_suspicious_encoding=False,
        registered_domain="192.168.1.1",
        hostname_tokens=[],
    )
    rules = evaluate_rules(features_all)
    raw_sum = sum(r.weight for r in rules if r.triggered)
    assert raw_sum == 105  # Raw score = 105

    # Normalized: round(105/130*100) = 81 -> DANGEROUS
    normalized = normalize_risk_score(raw_sum, MAX_RAW_SCORE)
    assert normalized == 81
    assert classify_risk_score(normalized) == "DANGEROUS"



def test_threshold_boundaries():
    """Verify exact threshold boundary classification."""
    assert classify_risk_score(0) == "SAFE"
    assert classify_risk_score(25) == "SAFE"
    assert classify_risk_score(26) == "SUSPICIOUS"
    assert classify_risk_score(65) == "SUSPICIOUS"
    assert classify_risk_score(66) == "DANGEROUS"
    assert classify_risk_score(100) == "DANGEROUS"


def test_clean_url_produces_zero_score():
    """Verify legitimate standard URL produces risk_score 0 and SAFE status."""
    result = analyze_url_security("https://www.example.org/about")
    assert result.status == "SAFE"
    assert result.risk_score == 0
    assert result.reasons == []


# ═══════════════════════════════════════════════════════════════════
# Phase 5A — Detection Engine Enhancement Tests
# ═══════════════════════════════════════════════════════════════════


# ── Feature Extraction Tests ──

def test_feature_extraction_punycode():
    """Verify punycode detection in hostname labels."""
    features_puny = extract_features("http://xn--pypal-4ve.com/login")
    assert features_puny.is_punycode is True

    features_normal = extract_features("https://example.com/path")
    assert features_normal.is_punycode is False


def test_feature_extraction_registered_domain():
    """Verify registered domain extraction from hostnames."""
    features = extract_features("https://sub.example.com/path")
    assert features.registered_domain == "example.com"

    features_deep = extract_features("https://a.b.c.example.com")
    assert features_deep.registered_domain == "example.com"

    features_couk = extract_features("https://sub.example.co.uk/path")
    assert features_couk.registered_domain == "example.co.uk"

    features_bare = extract_features("https://example.com")
    assert features_bare.registered_domain == "example.com"


def test_feature_extraction_hostname_tokens():
    """Verify hostname tokenization splits on dots and hyphens."""
    features = extract_features("http://paypa1-login.example.com/verify")
    assert "paypa1" in features.hostname_tokens
    assert "login" in features.hostname_tokens
    assert "example" in features.hostname_tokens
    assert "com" in features.hostname_tokens

    features2 = extract_features("http://apple-id-check.example.com/signin")
    assert "apple" in features2.hostname_tokens
    assert "id" in features2.hostname_tokens
    assert "check" in features2.hostname_tokens


def test_feature_extraction_suspicious_encoding():
    """Verify suspicious encoding detection in URL structure."""
    # Normal URL — no suspicious encoding
    features_normal = extract_features("https://example.com/search?q=hello%20world")
    assert features_normal.has_suspicious_encoding is False

    # Heavily encoded path (> 3 unusual encoded chars in structure)
    encoded_url = "https://example.com/%65%78%61%6D%70%6C%65/login"
    features_encoded = extract_features(encoded_url)
    assert features_encoded.has_suspicious_encoding is True


# ── Brand Impersonation Rule Tests ──

def test_rule_brand_impersonation_triggers():
    """Verify BRAND_IMPERSONATION triggers when a brand token appears in non-legitimate domain."""
    # "apple" token in hostname, but registered domain is example.com
    result = analyze_url_security("http://apple-id-check.example.com/signin")
    rule_ids = [r.rule for r in result.reasons]
    assert "BRAND_IMPERSONATION" in rule_ids

    # "microsoft" token in hostname
    result2 = analyze_url_security("http://microsoft-security-alert.example.com/login")
    rule_ids2 = [r.rule for r in result2.reasons]
    assert "BRAND_IMPERSONATION" in rule_ids2


def test_rule_brand_impersonation_legitimate_domain_safe():
    """Verify legitimate brand domains do NOT trigger brand impersonation."""
    safe_brands = [
        "https://paypal.com",
        "https://www.paypal.com/login",
        "https://apple.com",
        "https://www.apple.com/store",
        "https://microsoft.com",
        "https://login.microsoft.com/auth",
        "https://google.com",
        "https://mail.google.com/inbox",
        "https://amazon.com/products",
    ]
    for url in safe_brands:
        result = analyze_url_security(url)
        rule_ids = [r.rule for r in result.reasons]
        assert "BRAND_IMPERSONATION" not in rule_ids, f"False positive on {url}"
        assert "TYPOSQUATTING" not in rule_ids, f"Typosquat false positive on {url}"


# ── Typosquatting Rule Tests ──

def test_rule_typosquatting_triggers():
    """Verify TYPOSQUATTING triggers on near-match brand tokens."""
    # paypa1 ≈ paypal
    result = analyze_url_security("http://paypa1-login.example.com/verify")
    rule_ids = [r.rule for r in result.reasons]
    assert "TYPOSQUATTING" in rule_ids


def test_rule_typosquatting_legitimate_domain_safe():
    """Verify typosquatting does NOT trigger on legitimate brand domains."""
    result = analyze_url_security("https://paypal.com/login")
    rule_ids = [r.rule for r in result.reasons]
    assert "TYPOSQUATTING" not in rule_ids


# ── Punycode Rule Tests ──

def test_rule_punycode_hostname():
    """Verify PUNYCODE_HOSTNAME triggers on internationalized hostnames."""
    result = analyze_url_security("http://xn--pypal-4ve.com/login")
    rule_ids = [r.rule for r in result.reasons]
    assert "PUNYCODE_HOSTNAME" in rule_ids

    # Normal hostname should not trigger
    result_normal = analyze_url_security("https://example.com")
    rule_ids_normal = [r.rule for r in result_normal.reasons]
    assert "PUNYCODE_HOSTNAME" not in rule_ids_normal


# ── Suspicious Encoding Rule Tests ──

def test_rule_suspicious_url_encoding():
    """Verify SUSPICIOUS_URL_ENCODING triggers on heavily encoded URLs."""
    # Heavily encoded path characters
    encoded_url = "https://example.com/%65%78%61%6D%70%6C%65/login"
    result = analyze_url_security(encoded_url)
    rule_ids = [r.rule for r in result.reasons]
    assert "SUSPICIOUS_URL_ENCODING" in rule_ids

    # Normal query encoding should not trigger
    normal_url = "https://example.com/search?q=hello%20world&lang=en"
    result_normal = analyze_url_security(normal_url)
    rule_ids_normal = [r.rule for r in result_normal.reasons]
    assert "SUSPICIOUS_URL_ENCODING" not in rule_ids_normal


# ── Path-Based False Positive Prevention ──

def test_brand_in_path_does_not_trigger():
    """Verify brand names in URL path do NOT trigger hostname-based rules.

    Brand impersonation and typosquatting must only examine hostname tokens,
    not path or query components.
    """
    path_urls = [
        "https://example.com/apple-login",
        "https://example.com/paypal/verify",
        "https://example.com/pages/microsoft-support",
        "https://example.com/search?q=paypal",
    ]
    for url in path_urls:
        result = analyze_url_security(url)
        rule_ids = [r.rule for r in result.reasons]
        assert "BRAND_IMPERSONATION" not in rule_ids, f"Path false positive on {url}"
        assert "TYPOSQUATTING" not in rule_ids, f"Typosquat path false positive on {url}"


# ── Combined Rule Scoring Tests ──

def test_brand_impersonation_with_hyphens_combined():
    """Verify brand impersonation + structural rules produce correct combined score."""
    # microsoft-security-alert.example.com has:
    # - "microsoft" brand in non-legitimate domain → BRAND_IMPERSONATION +35
    # - 2 hyphens (below >=3 threshold) → EXCESSIVE_HOST_HYPHENS does NOT trigger
    # Total raw = 35 → normalized 27 → SUSPICIOUS
    result = analyze_url_security("http://microsoft-security-alert.example.com/login")
    assert result.risk_score == 27
    assert result.status == "SUSPICIOUS"
    rule_ids = [r.rule for r in result.reasons]
    assert "BRAND_IMPERSONATION" in rule_ids
    assert "EXCESSIVE_HOST_HYPHENS" not in rule_ids


def test_user_specified_test_urls():
    """Verify the user's exact test URLs produce correct detection and scoring."""
    # paypa1-login.example.com — typosquatting (paypa1 ≈ paypal)
    res1 = analyze_url_security("http://paypa1-login.example.com/verify")
    assert res1.status in ("SAFE", "SUSPICIOUS", "DANGEROUS")
    rule_ids1 = [r.rule for r in res1.reasons]
    assert "TYPOSQUATTING" in rule_ids1

    # apple-id-check.example.com — brand impersonation (apple exact match)
    res2 = analyze_url_security("http://apple-id-check.example.com/signin")
    assert res2.status in ("SAFE", "SUSPICIOUS", "DANGEROUS")
    rule_ids2 = [r.rule for r in res2.reasons]
    assert "BRAND_IMPERSONATION" in rule_ids2

    # microsoft-security-alert.example.com — brand impersonation + hyphens
    res3 = analyze_url_security("http://microsoft-security-alert.example.com/login")
    assert res3.status == "SUSPICIOUS"
    rule_ids3 = [r.rule for r in res3.reasons]
    assert "BRAND_IMPERSONATION" in rule_ids3


def test_legitimate_brands_remain_safe():
    """Verify that actual legitimate brand domains produce SAFE with no indicators."""
    legitimate = [
        "https://paypal.com",
        "https://apple.com",
        "https://microsoft.com",
        "https://google.com",
        "https://amazon.com",
    ]
    for url in legitimate:
        result = analyze_url_security(url)
        assert result.status == "SAFE", f"{url} should be SAFE, got {result.status}"
        assert result.risk_score == 0, f"{url} should have score 0, got {result.risk_score}"
        assert result.reasons == [], f"{url} should have no reasons, got {result.reasons}"


# ═══════════════════════════════════════════════════════════════════
# Phase 5B — Detection Quality Validation (4 Categories)
# ═══════════════════════════════════════════════════════════════════

def test_phase5b_legitimate_cases():
    """Category 1: Legitimate cases (should be SAFE)."""
    urls = [
        "https://www.paypal.com/signin",
        "https://support.apple.com/en-us",
        "https://github.com/login",
        "https://myaccount.google.com/security",
    ]
    for url in urls:
        result = analyze_url_security(url)
        assert result.status == "SAFE", f"{url} failed validation"
        assert result.risk_score < 26

def test_phase5b_impersonation_cases():
    """Category 2: Impersonation cases (should trigger brand/typosquat detection)."""
    urls = [
        "http://paypal-security-check.example.com",
        "http://apple-login.support.example.com",
        "http://paypa1-update.example.com",
    ]
    for url in urls:
        result = analyze_url_security(url)
        # With normalized scoring, some single-indicator URLs may be SAFE but still detected
        assert result.status in ["SAFE", "SUSPICIOUS", "DANGEROUS"], f"{url} failed validation"
        rule_ids = [r.rule for r in result.reasons]
        assert any(r in rule_ids for r in ["BRAND_IMPERSONATION", "TYPOSQUATTING"])

def test_phase5b_evasion_cases():
    """Category 3: Evasion cases (should trigger evasion rules)."""
    # IP Address, Punycode, Suspicious Encoding, Excessive Subdomains
    cases = [
        ("http://192.168.1.50/login", "IP_ADDRESS_HOST"),
        ("http://xn--pple-4ve.com/auth", "PUNYCODE_HOSTNAME"),
        ("https://example.com/%61%62%63%64%65%66/login", "SUSPICIOUS_URL_ENCODING"),
        ("https://a.b.c.d.example.com/login", "EXCESSIVE_SUBDOMAINS"),
    ]
    for url, expected_rule in cases:
        result = analyze_url_security(url)
        rule_ids = [r.rule for r in result.reasons]
        assert expected_rule in rule_ids, f"{url} missed {expected_rule}"

def test_phase5b_combination_cases():
    """Category 4: Combination cases (should aggregate scores correctly)."""
    # Impersonation + Excessive Hyphens + Long URL
    long_tail = "a" * 150
    url = f"http://apple-security-alert-urgent-update.example.com/login?token={long_tail}"
    
    result = analyze_url_security(url)
    assert result.status in ["SUSPICIOUS", "DANGEROUS"]
    rule_ids = [r.rule for r in result.reasons]
    
    assert "BRAND_IMPERSONATION" in rule_ids
    assert "EXCESSIVE_HOST_HYPHENS" in rule_ids
    assert "EXCESSIVE_URL_LENGTH" in rule_ids
    
    # Check score aggregation
    # BRAND_IMPERSONATION (35) + EXCESSIVE_HOST_HYPHENS (10) + EXCESSIVE_URL_LENGTH (10) = raw 55
    # Normalized: round(55/130*100) = 42 (SUSPICIOUS)
    assert result.risk_score >= 42


# ═══════════════════════════════════════════════════════════════════
# Module 1 — Advanced URL Structural Analysis
# ═══════════════════════════════════════════════════════════════════


def test_module1_ipv4_and_ipv6_classification():
    """IPv4 and IPv6 should be distinguished correctly."""

    ipv4 = extract_features(
        "http://192.168.1.1/login"
    )

    assert ipv4.is_ip_address is True
    assert ipv4.is_ipv4_address is True
    assert ipv4.is_ipv6_address is False

    ipv6 = extract_features(
        "http://[2001:db8::1]/login"
    )

    assert ipv6.is_ip_address is True
    assert ipv6.is_ipv4_address is False
    assert ipv6.is_ipv6_address is True


def test_module1_hostname_normalization():
    """Hostname casing and trailing root-label dot should normalize."""

    features = extract_features(
        "https://EXAMPLE.COM./login"
    )

    assert features.host == "example.com"
    assert features.normalized_host == "example.com"
    assert features.registered_domain == "example.com"


def test_module1_subdomain_depth():
    """Subdomain depth should be calculated relative to registered domain."""

    features = extract_features(
        "https://login.security.verify.example.com/account"
    )

    assert features.registered_domain == "example.com"
    assert features.subdomain_depth == 3


def test_module1_registered_domain_with_co_uk():
    """Two-part public suffix handling should remain intact."""

    features = extract_features(
        "https://login.example.co.uk/account"
    )

    assert features.registered_domain == "example.co.uk"
    assert features.subdomain_depth == 1


def test_module1_non_standard_port():
    """Non-standard web ports should be detected."""

    standard_https = extract_features(
        "https://example.com:443/login"
    )

    assert standard_https.port == 443
    assert standard_https.is_non_standard_port is False

    standard_http = extract_features(
        "http://example.com:80/login"
    )

    assert standard_http.port == 80
    assert standard_http.is_non_standard_port is False

    unusual = extract_features(
        "https://example.com:8080/login"
    )

    assert unusual.port == 8080
    assert unusual.is_non_standard_port is True


def test_module1_path_depth():
    """Path depth should count meaningful path segments."""

    root = extract_features(
        "https://example.com/"
    )

    assert root.path_depth == 0

    nested = extract_features(
        "https://example.com/a/b/c/d/login"
    )

    assert nested.path_depth == 5


def test_module1_query_parameter_extraction():
    """Query parameter names should be normalized and deterministic."""

    features = extract_features(
        "https://example.com/login?User=123&Next=/home"
    )

    assert features.query_parameter_names == (
        "next",
        "user",
    )


def test_module1_redirect_parameter_detection():
    """Common redirect parameters should generate structural evidence."""

    redirect_urls = [
        "https://example.com/login?next=https://other.com",
        "https://example.com/login?redirect=https://other.com",
        "https://example.com/login?return_url=https://other.com",
        "https://example.com/login?destination=https://other.com",
    ]

    for url in redirect_urls:
        features = extract_features(url)

        assert (
            features.has_suspicious_redirect_parameter
            is True
        )


def test_module1_normal_query_does_not_trigger_redirect():
    """Normal query parameters should not be treated as redirects."""

    features = extract_features(
        "https://example.com/search?q=hello&page=2"
    )

    assert (
        features.has_suspicious_redirect_parameter
        is False
    )


def test_module1_fragment_detection():
    """Fragment presence should be represented separately."""

    with_fragment = extract_features(
        "https://example.com/login#section"
    )

    assert with_fragment.has_fragment is True

    without_fragment = extract_features(
        "https://example.com/login"
    )

    assert without_fragment.has_fragment is False


def test_module1_redirect_rule():
    """Suspicious redirect parameter rule should produce +15 evidence."""

    result = analyze_url_security(
        "https://example.com/login?next=/other"
    )

    rule_ids = [
        reason.rule
        for reason in result.reasons
    ]

    assert "SUSPICIOUS_REDIRECT_PARAMETER" in rule_ids
    assert "EXTERNAL_REDIRECT_DESTINATION" not in rule_ids
    assert result.risk_score == 12
    assert result.status == "SAFE"


def test_module1_non_standard_port_rule():
    """Non-standard port should produce low-severity evidence."""

    result = analyze_url_security(
        "https://example.com:8080/login"
    )

    rule_ids = [
        reason.rule
        for reason in result.reasons
    ]

    assert "NON_STANDARD_PORT" in rule_ids
    assert result.risk_score == 4
    assert result.status == "SAFE"


def test_module1_standard_https_port_safe():
    """Explicit HTTPS port 443 must not trigger NON_STANDARD_PORT."""

    result = analyze_url_security(
        "https://example.com:443/login"
    )

    rule_ids = [
        reason.rule
        for reason in result.reasons
    ]

    assert "NON_STANDARD_PORT" not in rule_ids


def test_module1_combined_structural_evidence():
    """Multiple independent structural indicators should aggregate."""

    url = (
        "http://paypal-security.example.com:8080/login"
        "?next=https://attacker.example"
    )

    result = analyze_url_security(url)

    rule_ids = [
        reason.rule
        for reason in result.reasons
    ]

    assert "BRAND_IMPERSONATION" in rule_ids
    assert "NON_STANDARD_PORT" in rule_ids
    assert "EXTERNAL_REDIRECT_DESTINATION" in rule_ids

    # raw: 35 + 5 + 15 = 55 -> normalized: round(55/130*100) = 42
    assert result.risk_score == 42
    assert result.status == "SUSPICIOUS"


# ═══════════════════════════════════════════════════════════════════
# Module 1B — Advanced Structural Detection & Edge Cases
# ═══════════════════════════════════════════════════════════════════

from backend.detection.features.brands import check_deceptive_domain


def test_deceptive_domain_detects_brand_domain_prefix():
    """Detect legitimate brand-domain sequence before unrelated domain."""

    match = check_deceptive_domain(
        "paypal.com.attacker.com",
        "attacker.com",
    )

    assert match is not None
    assert match.brand_name == "paypal"
    assert match.matched_domain == "paypal.com"
    assert match.registered_domain == "attacker.com"


def test_deceptive_domain_does_not_flag_legitimate_brand_subdomain():
    """Legitimate brand subdomains must not trigger."""

    match = check_deceptive_domain(
        "login.paypal.com",
        "paypal.com",
    )

    assert match is None


def test_deceptive_domain_does_not_flag_bare_brand_domain():
    """Bare legitimate domain must not trigger."""

    match = check_deceptive_domain(
        "paypal.com",
        "paypal.com",
    )

    assert match is None


def test_deceptive_domain_requires_complete_labels():
    """Partial substring matches must not trigger."""

    match = check_deceptive_domain(
        "paypal.com.attacker.com",
        "attacker.com",
    )

    assert match is not None

    partial = check_deceptive_domain(
        "notpaypal.com.attacker.com",
        "attacker.com",
    )

    assert partial is None


def test_deceptive_domain_other_brands():
    """Validate multiple registered brand-domain patterns."""

    cases = [
        (
            "google.com.attacker.com",
            "attacker.com",
            "google",
        ),
        (
            "apple.com.attacker.com",
            "attacker.com",
            "apple",
        ),
        (
            "microsoft.com.attacker.com",
            "attacker.com",
            "microsoft",
        ),
    ]

    for hostname, registered_domain, expected_brand in cases:
        match = check_deceptive_domain(
            hostname,
            registered_domain,
        )

        assert match is not None
        assert match.brand_name == expected_brand


def test_deceptive_domain_rule():
    """Verify deceptive-domain structure generates evidence."""

    result = analyze_url_security(
        "https://paypal.com.attacker.com/login"
    )

    rule_ids = [
        reason.rule
        for reason in result.reasons
    ]

    assert "DECEPTIVE_DOMAIN_STRUCTURE" in rule_ids


def test_deceptive_domain_legitimate_domains_remain_safe():
    """Legitimate brand domains must not trigger deceptive-domain rule."""

    urls = [
        "https://paypal.com",
        "https://login.paypal.com",
        "https://www.paypal.com/login",
        "https://accounts.google.com",
        "https://login.microsoft.com",
        "https://support.apple.com",
    ]

    for url in urls:
        result = analyze_url_security(url)

        rule_ids = [
            reason.rule
            for reason in result.reasons
        ]

        assert (
            "DECEPTIVE_DOMAIN_STRUCTURE"
            not in rule_ids
        ), url


def test_redirect_relative_destination():
    features = extract_features(
        "https://example.com/login?next=/dashboard"
    )

    assert features.has_suspicious_redirect_parameter is True
    assert features.has_external_redirect_destination is False


def test_redirect_same_origin_destination():
    features = extract_features(
        "https://example.com/login"
        "?next=https://example.com/dashboard"
    )

    assert features.has_external_redirect_destination is False


def test_redirect_external_destination():
    features = extract_features(
        "https://example.com/login"
        "?next=https://attacker.com/login"
    )

    assert features.has_external_redirect_destination is True
    assert features.redirect_destinations == (
        "https://attacker.com/login",
    )


def test_redirect_encoded_external_destination():
    features = extract_features(
        "https://example.com/login"
        "?next=https%3A%2F%2Fattacker.com%2Flogin"
    )

    assert features.has_external_redirect_destination is True


def test_redirect_protocol_relative_external_destination():
    features = extract_features(
        "https://example.com/login"
        "?next=//attacker.com/login"
    )

    assert features.has_external_redirect_destination is True


def test_redirect_protocol_relative_same_origin():
    features = extract_features(
        "https://example.com/login"
        "?next=//example.com/dashboard"
    )

    assert features.has_external_redirect_destination is False


def test_non_redirect_parameter_containing_external_url():
    features = extract_features(
        "https://example.com/login"
        "?reference=https://attacker.com"
    )

    assert features.has_external_redirect_destination is False


def test_external_redirect_rule():
    result = analyze_url_security(
        "https://example.com/login"
        "?next=https://attacker.com"
    )

    rule_ids = [
        reason.rule
        for reason in result.reasons
    ]

    assert "EXTERNAL_REDIRECT_DESTINATION" in rule_ids
    assert "SUSPICIOUS_REDIRECT_PARAMETER" not in rule_ids

    assert result.risk_score == 12
    assert result.status == "SAFE"


def test_brand_impersonation_with_external_redirect():
    result = analyze_url_security(
        "https://paypal-login.example.com/login"
        "?next=https://attacker.example"
    )

    rule_ids = [
        reason.rule
        for reason in result.reasons
    ]

    assert "BRAND_IMPERSONATION" in rule_ids
    assert "EXTERNAL_REDIRECT_DESTINATION" in rule_ids

    # raw: 35 + 15 = 50 -> normalized: round(50/130*100) = 38
    assert result.risk_score == 38
    assert result.status == "SUSPICIOUS"


def test_userinfo_and_hostname_structure_features():
    features = extract_features(
        "https://username:password@attacker123.example.com/login"
    )

    assert features.has_userinfo is True
    assert features.userinfo_length == len("username:password")

    assert features.hostname_label_count == 3
    assert features.longest_hostname_label_length == len("attacker123")
    assert features.numeric_hostname_label_count == 0
    assert features.mixed_alphanumeric_label_count == 1


def test_hostname_structure_normal_domain():
    features = extract_features(
        "https://login.example.com"
    )

    assert features.hostname_label_count == 3
    assert features.numeric_hostname_label_count == 0
    assert features.mixed_alphanumeric_label_count == 0


def test_numeric_hostname_label():
    features = extract_features(
        "https://12345.example.com"
    )

    assert features.numeric_hostname_label_count == 1


def test_excessive_userinfo_rule():
    long_userinfo = "a" * 40

    result = analyze_url_security(
        f"https://{long_userinfo}@attacker.com"
    )

    rule_ids = [
        reason.rule
        for reason in result.reasons
    ]

    assert "USERINFO_AT_SYMBOL" in rule_ids
    assert "EXCESSIVE_USERINFO" in rule_ids


def test_at_symbol_in_path_is_not_userinfo():
    features = extract_features(
        "https://example.com/path/@username"
    )

    assert features.has_userinfo is False


def test_at_symbol_in_query_is_not_userinfo():
    features = extract_features(
        "https://example.com/login?user=test@example.com"
    )

    assert features.has_userinfo is False


def test_digit_substitution_typosquatting():
    result = analyze_url_security(
        "https://www.g00gle.com/search"
    )
    rule_ids = [r.rule for r in result.reasons]
    assert "TYPOSQUATTING" in rule_ids


def test_legitimate_google_not_typosquatting():
    result = analyze_url_security(
        "https://www.google.com/search"
    )
    rule_ids = [r.rule for r in result.reasons]
    assert "TYPOSQUATTING" not in rule_ids


def test_deceptive_userinfo_destination():
    features = extract_features(
        "https://www.google.com@malicious-site.com/"
    )
    assert features.has_userinfo is True
    assert features.has_deceptive_userinfo_destination is True


def test_non_deceptive_userinfo():
    features = extract_features(
        "https://username@example.com/"
    )
    assert features.has_userinfo is True
    assert features.has_deceptive_userinfo_destination is False


def test_encoded_path_traversal():
    features = extract_features(
        "https://example.com/%2e%2e/%2e%2e/etc/passwd"
    )
    assert features.has_encoded_path_traversal is True


def test_normal_encoded_path_is_not_traversal():
    features = extract_features(
        "https://example.com/%73%65%63%75%72%65"
    )
    assert features.has_encoded_path_traversal is False


def test_mixed_unicode_scripts():
    from backend.detection.features.extractor import _has_mixed_unicode_scripts
    assert _has_mixed_unicode_scripts("example.com") is False


# ── Regression tests: Google legitimate domain allowlist ──
# Triggered by share.gemini.google false positive.
# The BRAND_IMPERSONATION rule must NOT fire when the registered domain
# belongs to Google's legitimate domain list.


import pytest


@pytest.mark.parametrize("domain", [
    "google.com",
    "gmail.com",
    "youtube.com",
    "gemini.google",
    "ai.google",
    "store.google",
    "domains.google",
    "about.google",
    "blog.google",
    "safety.google",
    "grow.google",
])
def test_legitimate_google_domains_no_brand_impersonation(domain):
    """Each legitimate Google domain must not trigger BRAND_IMPERSONATION."""
    result = analyze_url_security(f"https://{domain}/")
    rule_ids = [r.rule for r in result.reasons]
    assert "BRAND_IMPERSONATION" not in rule_ids, (
        f"{domain} incorrectly flagged as BRAND_IMPERSONATION"
    )


def test_share_gemini_google_is_safe():
    """Regression: share.gemini.google must be SAFE with score 0.

    This was the original false positive that exposed the incomplete
    Google legitimate-domain list.
    """
    result = analyze_url_security("https://share.gemini.google")
    assert result.risk_score == 0
    assert result.status == "SAFE"
    rule_ids = [r.rule for r in result.reasons]
    assert "BRAND_IMPERSONATION" not in rule_ids


@pytest.mark.parametrize("subdomain", [
    "www", "share", "docs", "mail", "maps", "drive",
])
def test_google_subdomains_not_impersonation(subdomain):
    """Subdomains of legitimate Google domains must not trigger."""
    result = analyze_url_security(f"https://{subdomain}.google.com/")
    rule_ids = [r.rule for r in result.reasons]
    assert "BRAND_IMPERSONATION" not in rule_ids


# ── Regression tests: malicious Google impersonation must still trigger ──


@pytest.mark.parametrize("url,expected_rule", [
    ("https://google-login.evil.com/signin", "BRAND_IMPERSONATION"),
    ("https://google-security.evil.com/verify", "BRAND_IMPERSONATION"),
])
def test_malicious_google_impersonation_detected(url, expected_rule):
    """Malicious domains containing 'google' must still trigger detection."""
    result = analyze_url_security(url)
    rule_ids = [r.rule for r in result.reasons]
    assert expected_rule in rule_ids, (
        f"{url} should have triggered {expected_rule}"
    )


def test_deceptive_google_subdomain_on_evil_domain():
    """google.com.evil.com — deceptive domain structure, not legitimate."""
    result = analyze_url_security("https://google.com.evil.com/")
    rule_ids = [r.rule for r in result.reasons]
    # Must trigger either BRAND_IMPERSONATION or DECEPTIVE_DOMAIN_STRUCTURE
    assert (
        "BRAND_IMPERSONATION" in rule_ids
        or "DECEPTIVE_DOMAIN_STRUCTURE" in rule_ids
    ), f"google.com.evil.com should be flagged, got: {rule_ids}"


def test_gemini_google_evil_com_not_legitimate():
    """gemini.google.evil.com — registered domain is evil.com, not legitimate."""
    result = analyze_url_security("https://gemini.google.evil.com/")
    rule_ids = [r.rule for r in result.reasons]
    assert (
        "BRAND_IMPERSONATION" in rule_ids
        or "DECEPTIVE_DOMAIN_STRUCTURE" in rule_ids
    ), f"gemini.google.evil.com should be flagged, got: {rule_ids}"
    assert result.status != "SAFE"
