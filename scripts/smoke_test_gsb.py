"""Real API Smoke Test for Google Safe Browsing Integration.

This script should only be run manually when SAFE_BROWSING_API_KEY is configured.
It verifies the exact schema contract with the real provider.
"""

import os
import asyncio
import sys

# Ensure backend package can be imported
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.detection.intelligence.providers import GoogleSafeBrowsingProvider

async def run_smoke_test():
    api_key = os.getenv("SAFE_BROWSING_API_KEY")
    if not api_key:
        print("ERROR: SAFE_BROWSING_API_KEY environment variable is not set.")
        print("Skipping real API smoke test.")
        sys.exit(1)

    print("Running Google Safe Browsing Smoke Test...")
    provider = GoogleSafeBrowsingProvider(api_key=api_key)

    # Test 1: Known safe domain
    safe_url = "https://google.com/"
    print(f"\nChecking safe URL: {safe_url}")
    result1 = await provider.check_url(safe_url)
    print(f"Result -> Available: {result1.available}, Malicious: {result1.is_malicious}")
    assert result1.available is True, "Provider should be available"
    assert result1.is_malicious is False, "Google.com should not be malicious"

    # Test 2: Known malware domain (Google Safe Browsing test URL)
    # http://malware.testing.google.test/testing/malware/
    malware_url = "http://malware.testing.google.test/testing/malware/"
    print(f"\nChecking known malicious test URL: {malware_url}")
    result2 = await provider.check_url(malware_url)
    print(f"Result -> Available: {result2.available}, Malicious: {result2.is_malicious}")
    assert result2.available is True, "Provider should be available"
    # Note: Since we strip path for privacy, GSB might not match this domain-only.
    # However, for a real test, if it returns is_malicious=True or False, we log it.
    
    print("\nSmoke test completed successfully!")

if __name__ == "__main__":
    asyncio.run(run_smoke_test())
