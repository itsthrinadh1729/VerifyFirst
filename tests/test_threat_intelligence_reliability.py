import pytest
from backend.detection.intelligence.schemas import ThreatIntelResult
from backend.detection.intelligence.service import ThreatIntelService
from backend.detection.analysis.fusion import fuse_evidence
from backend.detection.engine.scorer import analyze_url_security


class TimeoutProvider:
    @property
    def name(self):
        return "timeout_provider"

    async def check_url(self, url):
        raise TimeoutError("Provider timed out")


@pytest.mark.asyncio
async def test_provider_timeout_returns_unavailable():
    service = ThreatIntelService(provider=TimeoutProvider())
    result = await service.check_url("https://example.com")

    assert isinstance(result, ThreatIntelResult)
    assert result.available is False
    assert result.is_malicious is False
    assert result.confidence == "unknown"


class ConnectionFailureProvider:
    @property
    def name(self):
        return "connection_failure_provider"

    async def check_url(self, url):
        raise ConnectionError("Connection failed")


@pytest.mark.asyncio
async def test_connection_failure_returns_unavailable():
    service = ThreatIntelService(provider=ConnectionFailureProvider())
    result = await service.check_url("https://example.com")

    assert result.available is False
    assert result.is_malicious is False
    assert result.confidence == "unknown"


class BrokenProvider:
    @property
    def name(self):
        return "broken_provider"

    async def check_url(self, url):
        raise RuntimeError("Unexpected provider failure")


@pytest.mark.asyncio
async def test_unexpected_provider_error_is_contained():
    service = ThreatIntelService(provider=BrokenProvider())
    result = await service.check_url("https://example.com")

    assert result.available is False
    assert result.is_malicious is False
    assert result.confidence == "unknown"


class MalformedProvider:
    @property
    def name(self):
        return "malformed_provider"

    async def check_url(self, url):
        return None


@pytest.mark.asyncio
async def test_malformed_provider_response_is_unavailable():
    service = ThreatIntelService(provider=MalformedProvider())
    result = await service.check_url("https://example.com")

    assert result.available is False
    assert result.is_malicious is False


class InvalidObjectProvider:
    @property
    def name(self):
        return "invalid_object_provider"

    async def check_url(self, url):
        return {"malicious": True}


@pytest.mark.asyncio
async def test_invalid_provider_object_is_unavailable():
    service = ThreatIntelService(provider=InvalidObjectProvider())
    result = await service.check_url("https://example.com")

    assert result.available is False
    assert result.is_malicious is False


class HealthyProvider:
    @property
    def name(self):
        return "healthy_provider"

    async def check_url(self, url):
        return ThreatIntelResult(
            available=True,
            is_malicious=True,
            confidence="high",
            source="healthy_provider",
            reason="Known threat",
        )


@pytest.mark.asyncio
async def test_healthy_provider_result_is_preserved():
    service = ThreatIntelService(provider=HealthyProvider())
    result = await service.check_url("https://example.com")

    assert result.available is True
    assert result.is_malicious is True
    assert result.confidence == "high"
    assert result.source == "healthy_provider"
    assert result.reason == "Known threat"


@pytest.mark.asyncio
async def test_intelligence_failure_does_not_override_heuristics():
    url = "https://paypal.com.attacker.com"
    heuristic = analyze_url_security(url)
    service = ThreatIntelService(provider=TimeoutProvider())
    intelligence = await service.check_url(url)
    fused = fuse_evidence(heuristic, intelligence)

    assert intelligence.available is False
    assert fused.risk_score == heuristic.risk_score
    assert fused.status == heuristic.status
    assert fused.reasons == heuristic.reasons


class MaliciousProvider:
    @property
    def name(self):
        return "malicious_provider"

    async def check_url(self, url):
        return ThreatIntelResult(
            available=True,
            is_malicious=True,
            confidence="high",
            source="malicious_provider",
            reason="Known malicious URL",
        )


@pytest.mark.asyncio
async def test_intelligence_match_still_forces_dangerous():
    url = "https://example.com"
    heuristic = analyze_url_security(url)
    service = ThreatIntelService(provider=MaliciousProvider())
    intelligence = await service.check_url(url)
    fused = fuse_evidence(heuristic, intelligence)

    assert intelligence.available is True
    assert intelligence.is_malicious is True
    assert fused.status == "DANGEROUS"
    assert fused.risk_score == 100


class RecoveringProvider:
    @property
    def name(self):
        return "recovering_provider"

    def __init__(self):
        self.calls = 0

    async def check_url(self, url):
        self.calls += 1
        if self.calls == 1:
            raise TimeoutError("Temporary failure")

        return ThreatIntelResult(
            available=True,
            is_malicious=True,
            confidence="high",
            source=self.name,
            reason="Recovered threat lookup",
        )


@pytest.mark.asyncio
async def test_unavailable_result_is_not_cached():
    provider = RecoveringProvider()
    service = ThreatIntelService(provider=provider)
    url = "https://example.com"

    first = await service.check_url(url)
    second = await service.check_url(url)

    assert first.available is False
    assert second.available is True
    assert second.is_malicious is True
    assert provider.calls == 2


@pytest.mark.asyncio
async def test_successful_result_is_cached():
    provider = RecoveringProvider()
    provider.calls = 1  # Make it succeed immediately
    service = ThreatIntelService(provider=provider)
    url = "https://example.com"

    first = await service.check_url(url)
    second = await service.check_url(url)

    assert first.available is True
    assert second.available is True
    assert provider.calls == 2
