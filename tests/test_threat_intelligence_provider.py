import pytest
from backend.detection.intelligence.providers import (
    GoogleSafeBrowsingProvider,
    ThreatIntelProvider,
)
from backend.detection.intelligence.schemas import ThreatIntelResult
from backend.detection.intelligence.service import ThreatIntelService


def test_google_safe_browsing_provider_has_name():
    provider = GoogleSafeBrowsingProvider()

    assert provider.name == "google_safe_browsing"


class FakeThreatIntelProvider:
    @property
    def name(self) -> str:
        return "fake_provider"

    def __init__(self, result):
        self.result = result
        self.lookups = []

    async def check_url(self, url: str):
        self.lookups.append(url)
        return self.result


@pytest.mark.asyncio
async def test_fake_provider_satisfies_contract():
    result = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="fake_provider",
        reason="Test threat match",
    )

    provider = FakeThreatIntelProvider(result)

    assert provider.name == "fake_provider"

    returned = await provider.check_url(
        "https://example.com"
    )

    assert returned == result


@pytest.mark.asyncio
async def test_provider_receives_url():
    result = ThreatIntelResult.unavailable()

    provider = FakeThreatIntelProvider(result)

    url = "https://example.com/login"

    await provider.check_url(url)

    assert provider.lookups == [url]


@pytest.mark.asyncio
async def test_service_accepts_custom_provider():
    result = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="fake_provider",
        reason="Test threat match",
    )

    provider = FakeThreatIntelProvider(result)

    service = ThreatIntelService(
        provider=provider
    )

    returned = await service.check_url(
        "https://example.com"
    )

    assert returned == result


@pytest.mark.asyncio
async def test_service_uses_cached_intelligence_result():
    result = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="fake_provider",
        reason="Test threat match",
    )

    provider = FakeThreatIntelProvider(result)

    service = ThreatIntelService(
        provider=provider
    )

    url = "https://example.com/path"

    first = await service.check_url(url)
    second = await service.check_url(url)

    assert first == second
    assert len(provider.lookups) == 1


@pytest.mark.asyncio
async def test_unavailable_intelligence_is_not_malicious():
    result = ThreatIntelResult.unavailable()

    provider = FakeThreatIntelProvider(result)

    service = ThreatIntelService(
        provider=provider
    )

    returned = await service.check_url(
        "https://example.com"
    )

    assert returned.available is False
    assert returned.is_malicious is False
    assert returned.confidence == "unknown"
