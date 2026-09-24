"""Threat Intelligence Providers."""

import os
import logging
from typing import Protocol
from urllib.parse import urlsplit
import httpx

from backend.detection.intelligence.schemas import ThreatIntelResult

logger = logging.getLogger(__name__)


def normalize_confidence(value) -> str:
    if isinstance(value, str):
        normalized = value.strip().lower()

        if normalized in {"high", "medium", "low"}:
            return normalized

        if normalized in {"unknown", "unavailable"}:
            return "unknown"

    if isinstance(value, (int, float)):
        if not 0.0 <= value <= 1.0:
            return "unknown"

        if value >= 0.80:
            return "high"

        if value >= 0.50:
            return "medium"

        return "low"

    return "unknown"


def normalize_threat_intel_result(
    *,
    available: bool,
    is_malicious: bool,
    confidence,
    source: str | None,
    reason: str | None,
) -> ThreatIntelResult:
    normalized_available = bool(available)

    # An unavailable intelligence result must never
    # be interpreted as a malicious match.
    if not normalized_available:
        return ThreatIntelResult.unavailable()

    normalized_confidence = normalize_confidence(confidence)

    return ThreatIntelResult(
        available=True,
        is_malicious=bool(is_malicious),
        confidence=normalized_confidence,
        source=source,
        reason=reason,
    )


class ThreatIntelProvider(Protocol):
    @property
    def name(self) -> str:
        ...

    async def check_url(self, url: str) -> ThreatIntelResult:
        ...


class GoogleSafeBrowsingProvider:
    """Google Safe Browsing v4 API implementation."""

    @property
    def name(self) -> str:
        return "google_safe_browsing"

    API_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    CLIENT_ID = "verifyfirst"
    CLIENT_VERSION = "0.1.0"

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.getenv("SAFE_BROWSING_API_KEY")
        self._client: httpx.AsyncClient | None = None

    async def start(self) -> None:
        """Start the reusable HTTP client."""
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=2.0)

    async def stop(self) -> None:
        """Stop the reusable HTTP client."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _get_privacy_preserving_domain_url(self, url: str) -> str:
        """
        Strips path, query parameters, and fragments from the URL.
        Returns just the scheme://hostname/ format for privacy-preserving lookup.
        """
        try:
            parsed = urlsplit(url)
            # Ensure scheme and hostname exist
            if not parsed.scheme or not parsed.hostname:
                return url
            return f"{parsed.scheme}://{parsed.hostname}/"
        except Exception:
            return url

    async def check_url(self, url: str) -> ThreatIntelResult:
        """
        Check the URL against Google Safe Browsing using a domain-only lookup
        to preserve user privacy.
        """
        if not self.api_key:
            return normalize_threat_intel_result(
                available=False,
                is_malicious=False,
                confidence="unknown",
                source=self.name,
                reason=None,
            )
            
        # Ensure client exists (in case lifespan was not called in tests)
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=2.0)

        safe_url = self._get_privacy_preserving_domain_url(url)

        payload = {
            "client": {
                "clientId": self.CLIENT_ID,
                "clientVersion": self.CLIENT_VERSION
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": safe_url}]
            }
        }

        try:
            # Reusing the application-lifetime client
            response = await self._client.post(
                f"{self.API_URL}?key={self.api_key}",
                json=payload
            )

            if response.status_code != 200:
                logger.error(f"Threat intelligence provider returned status {response.status_code}")
                return normalize_threat_intel_result(
                    available=False,
                    is_malicious=False,
                    confidence="unknown",
                    source=self.name,
                    reason=None,
                )

            data = response.json()
            matches = data.get("matches", [])

            if matches:
                # If there are any matches, it's considered malicious
                return normalize_threat_intel_result(
                    available=True,
                    is_malicious=True,
                    confidence="high",
                    source=self.name,
                    reason="Domain has been flagged by Google Safe Browsing."
                )

            return normalize_threat_intel_result(
                available=True,
                is_malicious=False,
                confidence="high",
                source=self.name,
                reason=None,
            )

        except httpx.TimeoutException:
            logger.error("Threat intelligence provider timeout")
            return normalize_threat_intel_result(
                available=False,
                is_malicious=False,
                confidence="unknown",
                source=self.name,
                reason=None,
            )
        except httpx.RequestError as exc:
            logger.error("Threat intelligence provider network error")
            return normalize_threat_intel_result(
                available=False,
                is_malicious=False,
                confidence="unknown",
                source=self.name,
                reason=None,
            )
        except Exception as exc:
            logger.error("Threat intelligence provider unexpected error")
            return normalize_threat_intel_result(
                available=False,
                is_malicious=False,
                confidence="unknown",
                source=self.name,
                reason=None,
            )
