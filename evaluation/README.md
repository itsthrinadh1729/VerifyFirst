# VerifyFirst Phase 16 Evaluation Dataset

This dataset provides the foundational baseline for evaluating the VerifyFirst deterministic heuristic engine and Google Safe Browsing integration. It is used to determine whether a Machine Learning model is technically necessary.

## Dataset Structure

* **Size**: 50 URLs
* **SAFE**: 25 URLs
* **PHISHING**: 24 URLs
* **UNKNOWN**: 1 URL
* **Format**: `url, actual_label, category`

## Ground Truth Methodology

The ground truth labels in this dataset are established using the following strict criteria:

1. **SAFE**: Confirmed legitimate domains representing a diverse cross-section of high-traffic web applications, corporate sites, and popular brands (e.g., `microsoft.com`, `paypal.com`, `github.com`).
2. **PHISHING**: Manually constructed or confirmed examples of well-known phishing vectors. These include typosquatting (e.g., `rnicrosoft.com`), brand impersonation in subdomains (`apple.id-verification...`), bare IP addresses (`103.25.12.3`), Punycode abuse (`xn--pypal-4qa.com`), excessive encoding, and explicit test domains used by Google Safe Browsing (`ianfette.org`).
3. **UNKNOWN**: URLs whose intent cannot be fully verified independently. These are excluded from strict precision/recall metrics.

## Strict Data Leakage Prevention

**None** of the URLs in this dataset appear in the `tests/` directory (e.g., `paypa1-login.example.com` or `apple-id-check.example.com` which the engine was explicitly TDD-tested against). This ensures the evaluation scripts measure the engine's generalization capabilities, rather than its ability to memorize unit tests.

## Categories Represented

* `legitimate`: Standard safe domains.
* `typosquatting`: Visual similarity to known brands.
* `brand_impersonation`: Deceptive use of brand names in the domain structure.
* `ip_address`: Raw IPv4 addresses bypassing DNS.
* `userinfo`: Abuse of the `@` symbol in the URL.
* `subdomain`: Excessive subdomains simulating complex phishing infrastructure.
* `long_url`: Exceedingly long URLs meant to overflow UI bounds.
* `punycode`: Homograph attacks using IDN representation.
* `encoding`: Obfuscated payloads in the path or query.
* `known_threat`: Test entries designed to trigger Threat Intelligence providers.
* `multi_rule`: URLs designed to trigger 3+ distinct rules simultaneously.
