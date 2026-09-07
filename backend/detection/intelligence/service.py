"""Threat Intelligence Service Layer."""

from backend.detection.intelligence.schemas import ThreatIntelResult
from backend.detection.intelligence.providers import BaseThreatIntelProvider, GoogleSafeBrowsingProvider


from urllib.parse import urlsplit
import time

class ThreatIntelService:
    """Orchestrates threat intelligence lookups using configured providers."""

    # 10 minutes cache TTL
    CACHE_TTL_SECONDS = 600

    def __init__(self, provider: BaseThreatIntelProvider = None):
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

    def _get_domain_key(self, url: str) -> str:
        try:
            parsed = urlsplit(url)
            return parsed.hostname or url
        except Exception:
            return url

    async def check_url(self, url: str) -> ThreatIntelResult:
        """
        Query the configured threat intelligence provider for the given URL,
        utilizing a domain-level TTL cache for performance.
        """
        domain_key = self._get_domain_key(url)
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
        result = await self.provider.check_url(url)
        
        # Only cache successful lookups (both matches and no-matches), not failures/unavailable
        if result.available:
            self._cache[domain_key] = (now, result)
            
        return result
