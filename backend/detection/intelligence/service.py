"""Threat Intelligence Service Layer."""

from backend.detection.intelligence.schemas import ThreatIntelResult
from backend.detection.intelligence.providers import ThreatIntelProvider, GoogleSafeBrowsingProvider


from urllib.parse import urlsplit
import time
import logging
import httpx

logger = logging.getLogger(__name__)

class ThreatIntelService:
    """Orchestrates threat intelligence lookups using configured providers."""

    # 10 minutes cache TTL
    CACHE_TTL_SECONDS = 600

    def __init__(self, provider: ThreatIntelProvider | None = None):
        # Default to GSB if no provider injected (e.g. for testing)
        self.provider = provider or GoogleSafeBrowsingProvider()
        
        # Cache for domain-level lookups: { "example.com": (timestamp, result) }
        self._cache: dict[str, tuple[float, ThreatIntelResult]] = {}

    async def start(self) -> None:
        """Start underlying provider resources."""
        if hasattr(self.provider, "start"):
            await self.provider.start()

    async def stop(self) -> None:
        """Stop underlying provider resources."""
        if hasattr(self.provider, "stop"):
            await self.provider.stop()

    def _get_domain_key(self, url: str) -> str | None:
        try:
            parsed = urlsplit(url)
            if not parsed.hostname:
                return None
            return parsed.hostname.rstrip(".").lower()
        except Exception:
            return None

    async def check_url(self, url: str) -> ThreatIntelResult:
        """
        Query the configured threat intelligence provider for the given URL,
        utilizing a domain-level TTL cache for performance.
        """
        domain_key = self._get_domain_key(url)
        if not domain_key:
            return ThreatIntelResult.unavailable()

        now = time.time()
        
        # Cache check
        if domain_key in self._cache:
            timestamp, cached_result = self._cache[domain_key]
            if (now - timestamp) < self.CACHE_TTL_SECONDS:
                return cached_result
            else:
                # Expired
                del self._cache[domain_key]

        # Cache miss or expired
        try:
            result = await self.provider.check_url(domain_key)
        except httpx.TimeoutException:
            logger.warning("Threat intelligence provider timeout: provider=%s domain=%s", self.provider.name, domain_key)
            return ThreatIntelResult.unavailable()
        except httpx.RequestError:
            logger.warning("Threat intelligence provider network error: provider=%s domain=%s", self.provider.name, domain_key)
            return ThreatIntelResult.unavailable()
        except TimeoutError:
            logger.warning("Threat intelligence provider timeout: provider=%s domain=%s", self.provider.name, domain_key)
            return ThreatIntelResult.unavailable()
        except ConnectionError:
            logger.warning("Threat intelligence provider network error: provider=%s domain=%s", self.provider.name, domain_key)
            return ThreatIntelResult.unavailable()
        except Exception:
            logger.warning("Threat intelligence provider unexpected error: provider=%s domain=%s", self.provider.name, domain_key)
            return ThreatIntelResult.unavailable()
        
        if not isinstance(result, ThreatIntelResult):
            logger.warning("Threat intelligence provider returned invalid result: provider=%s domain=%s", self.provider.name, domain_key)
            return ThreatIntelResult.unavailable()

        if not result.available:
            return ThreatIntelResult.unavailable()
        
        # Only cache successful lookups (both matches and no-matches), not failures/unavailable
        if result.available:
            self._cache[domain_key] = (now, result)
            
        return result
