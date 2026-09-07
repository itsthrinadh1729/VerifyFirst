"""Threat Intelligence Providers."""

import abc
import os
import logging
from urllib.parse import urlsplit
import httpx

from backend.detection.intelligence.schemas import ThreatIntelResult

logger = logging.getLogger(__name__)


class BaseThreatIntelProvider(abc.ABC):
    """Abstract base class for all threat intelligence providers."""

    @abc.abstractmethod
    async def check_url(self, url: str) -> ThreatIntelResult:
        """Check a URL against the threat intelligence source."""
        pass


class GoogleSafeBrowsingProvider(BaseThreatIntelProvider):
    """Google Safe Browsing v4 API implementation."""

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
            return ThreatIntelResult.unavailable()
            
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
                return ThreatIntelResult.unavailable()

            data = response.json()
            matches = data.get("matches", [])

            if matches:
                # If there are any matches, it's considered malicious
                return ThreatIntelResult(
                    available=True,
                    is_malicious=True,
                    confidence="high",
                    source="Google Safe Browsing",
                    reason="Domain has been flagged by Google Safe Browsing."
                )

            return ThreatIntelResult(
                available=True,
                is_malicious=False,
                confidence="high",
                source="Google Safe Browsing",
                reason=None
            )

        except httpx.TimeoutException:
            logger.error("Threat intelligence provider timeout")
            return ThreatIntelResult.unavailable()
        except httpx.RequestError as exc:
            logger.error("Threat intelligence provider network error")
            return ThreatIntelResult.unavailable()
        except Exception as exc:
            logger.error("Threat intelligence provider unexpected error")
            return ThreatIntelResult.unavailable()
