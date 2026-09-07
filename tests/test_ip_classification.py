"""Direct test of backend classification for IP-based URLs."""

from backend.detection.engine.scorer import analyze_url_security
from backend.detection.features.extractor import extract_features

urls = [
    "http://192.168.1.1/admin",
    "http://192.0.2.146/login/secure",
    "https://testsafebrowsing.appspot.com/s/phishing.html",
    "http://10.0.0.1/admin",
    "http://127.0.0.1/test",
    "http://localhost:8000/test",
    "https://open.spotify.com/track/123",
]

print("=" * 70)
print("URL CLASSIFICATION ANALYSIS")
print("=" * 70)

for url in urls:
    features = extract_features(url)
    result = analyze_url_security(url)

    print(f"\nURL: {url}")
    print(f"  is_ip_address: {features.is_ip_address}")
    print(f"  host: {features.host}")
    print(f"  registered_domain: {features.registered_domain}")
    print(f"  hostname_tokens: {features.hostname_tokens}")
    print(f"  STATUS: {result.status}")
    print(f"  SCORE:  {result.risk_score}")
    if result.reasons:
        for r in result.reasons:
            print(f"    RULE: {r.rule} -> {r.message}")
    else:
        print(f"    (no rules triggered)")
    print("-" * 70)
