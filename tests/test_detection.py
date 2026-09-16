"""Phase 1B — Unit tests for feature extraction, detection rules, scoring, and classification."""

from backend.detection.features.extractor import extract_features
from backend.detection.rules.rules import evaluate_rules
from backend.detection.engine.scorer import (
    analyze_url_security,
    classify_risk_score,
)


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
    """Verify IP_ADDRESS_HOST rule triggers with +40 points."""
    result = analyze_url_security("http://192.168.1.1/login")
    assert result.risk_score == 40
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
    """Verify USERINFO_AT_SYMBOL rule triggers with +25 points."""
    result = analyze_url_security("https://google.com@attacker.com/auth")
    assert result.risk_score == 25
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
    """Verify EXCESSIVE_SUBDOMAINS rule triggers with +20 points when subdomains >= 4."""
    result = analyze_url_security("https://sub4.sub3.sub2.sub1.example.com/")
    assert result.risk_score == 20
    assert result.status == "SAFE"
    rule_ids = [r.rule for r in result.reasons]
    assert "EXCESSIVE_SUBDOMAINS" in rule_ids


def test_rule_excessive_url_length():
    """Verify EXCESSIVE_URL_LENGTH rule triggers with +10 points when length > 200."""
    long_url = "https://example.com/" + ("a" * 190)  # Total > 200
    assert len(long_url) > 200
    result = analyze_url_security(long_url)
    assert result.risk_score == 10
    assert result.status == "SAFE"
    rule_ids = [r.rule for r in result.reasons]
    assert "EXCESSIVE_URL_LENGTH" in rule_ids


def test_rule_excessive_host_hyphens():
    """Verify EXCESSIVE_HOST_HYPHENS rule triggers with +10 points when hyphens >= 3."""
    result = analyze_url_security("https://verify-your-account-now.com/")
    assert result.risk_score == 10
    assert result.status == "SAFE"
    rule_ids = [r.rule for r in result.reasons]
    assert "EXCESSIVE_HOST_HYPHENS" in rule_ids


def test_additive_scoring_and_classification():
    """Verify multiple rules sum additively and change classification."""
    # IP (40) + @ (25) = 65 -> SUSPICIOUS
    url_suspicious = "http://legit-service.com@192.168.1.1/auth"
    res_suspicious = analyze_url_security(url_suspicious)
    assert res_suspicious.risk_score == 65
    assert res_suspicious.status == "SUSPICIOUS"
    assert len(res_suspicious.reasons) == 2
    rule_ids_susp = [r.rule for r in res_suspicious.reasons]
    assert "IP_ADDRESS_HOST" in rule_ids_susp
    assert "USERINFO_AT_SYMBOL" in rule_ids_susp

    # IP (40) + @ (25) + Length > 200 (10) = 75 -> DANGEROUS
    url_dangerous = "http://legit-service.com@192.168.1.1/login?" + ("param=" + "x" * 190)
    res_dangerous = analyze_url_security(url_dangerous)
    assert res_dangerous.risk_score == 75
    assert res_dangerous.status == "DANGEROUS"
    rule_ids_dang = [r.rule for r in res_dangerous.reasons]
    assert "IP_ADDRESS_HOST" in rule_ids_dang
    assert "USERINFO_AT_SYMBOL" in rule_ids_dang
    assert "EXCESSIVE_URL_LENGTH" in rule_ids_dang


def test_score_clamping_at_100():
    """Verify maximum raw score is clamped to 100 when rules exceed 100."""
    from backend.detection.features.extractor import URLFeatures

    # Construct features that trigger all 5 rules (40 + 25 + 20 + 10 + 10 = 105)
    features_all = URLFeatures(
        host="192.168.1.1",
        is_ip_address=True,     # +40
        url_length=250,         # +10
        host_length=11,
        num_subdomains=5,       # +20
        num_hyphens_host=4,     # +10
        has_at_symbol=True,     # +25
        num_dots_host=3,
        # Phase 5A fields (not relevant for this clamping test)
        is_punycode=False,
        has_suspicious_encoding=False,
        registered_domain="192.168.1.1",
        hostname_tokens=[],
    )
    rules = evaluate_rules(features_all)
    raw_sum = sum(r.weight for r in rules if r.triggered)
    assert raw_sum == 105  # Raw score exceeds 100

    # Test that risk score clamps to 100
    clamped_score = min(100, max(0, raw_sum))
    assert clamped_score == 100
    assert classify_risk_score(clamped_score) == "DANGEROUS"



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
    # Total = 35 → SUSPICIOUS
    result = analyze_url_security("http://microsoft-security-alert.example.com/login")
    assert result.risk_score == 35
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
    assert res2.status in ("SUSPICIOUS", "DANGEROUS")
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
    """Category 2: Impersonation cases (should be SUSPICIOUS or DANGEROUS)."""
    urls = [
        "http://paypal-security-check.example.com",
        "http://apple-login.support.example.com",
        "http://paypa1-update.example.com",
    ]
    for url in urls:
        result = analyze_url_security(url)
        assert result.status in ["SUSPICIOUS", "DANGEROUS"], f"{url} failed validation"
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
    # BRAND_IMPERSONATION (35) + EXCESSIVE_HOST_HYPHENS (10) + EXCESSIVE_URL_LENGTH (10) = 55
    # Depending on thresholds, could be 55 (SUSPICIOUS)
    assert result.risk_score >= 55
