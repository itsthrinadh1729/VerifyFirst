import pytest
import time
from unittest.mock import patch
from backend.detection.intelligence.service import ThreatIntelService
from backend.detection.intelligence.schemas import ThreatIntelResult

class RecordingProvider:
    @property
    def name(self):
        return "recording_provider"

    def __init__(self):
        self.urls = []

    async def check_url(self, url):
        self.urls.append(url)
        return ThreatIntelResult(
            available=True,
            is_malicious=False,
            confidence="low",
            source=self.name,
            reason=None,
        )

def test_cache_key_contains_only_hostname():
    service = ThreatIntelService()
    assert service._get_domain_key("https://example.com/login?token=secret#section") == "example.com"

@pytest.mark.asyncio
async def test_provider_does_not_receive_query_parameters():
    provider = RecordingProvider()
    service = ThreatIntelService(provider=provider)
    await service.check_url("https://example.com/login?token=SECRET123")
    assert provider.urls == ["example.com"]

@pytest.mark.asyncio
async def test_provider_does_not_receive_path():
    provider = RecordingProvider()
    service = ThreatIntelService(provider=provider)
    await service.check_url("https://example.com/private/account/reset")
    assert provider.urls == ["example.com"]

@pytest.mark.asyncio
async def test_provider_does_not_receive_fragment():
    provider = RecordingProvider()
    service = ThreatIntelService(provider=provider)
    await service.check_url("https://example.com/login#private-section")
    assert provider.urls == ["example.com"]

@pytest.mark.asyncio
async def test_provider_does_not_receive_userinfo():
    provider = RecordingProvider()
    service = ThreatIntelService(provider=provider)
    await service.check_url("https://username:password@example.com/login")
    assert provider.urls == ["example.com"]

@pytest.mark.asyncio
async def test_sensitive_url_components_do_not_create_separate_cache_entries():
    provider = RecordingProvider()
    service = ThreatIntelService(provider=provider)
    await service.check_url("https://example.com/login?token=AAA")
    await service.check_url("https://example.com/login?token=BBB")
    assert len(provider.urls) == 1

def test_hostname_cache_key_is_case_insensitive():
    service = ThreatIntelService()
    first = service._get_domain_key("https://EXAMPLE.COM/login")
    second = service._get_domain_key("https://example.com/login")
    assert first == second == "example.com"

def test_trailing_dot_is_normalized():
    service = ThreatIntelService()
    assert service._get_domain_key("https://example.com./login") == "example.com"

def test_port_is_not_part_of_domain_cache_key():
    service = ThreatIntelService()
    assert service._get_domain_key("https://example.com:8443/login") == "example.com"

@pytest.mark.asyncio
@patch("backend.detection.intelligence.service.time.time")
async def test_cache_expiration(mock_time):
    provider = RecordingProvider()
    service = ThreatIntelService(provider=provider)
    
    # t = 0: Cache miss
    mock_time.return_value = 0.0
    await service.check_url("https://example.com")
    assert len(provider.urls) == 1
    
    # t = 599: Cache hit
    mock_time.return_value = 599.0
    await service.check_url("https://example.com")
    assert len(provider.urls) == 1
    
    # t = 601: Cache expired, new fetch
    mock_time.return_value = 601.0
    await service.check_url("https://example.com")
    assert len(provider.urls) == 2

def test_cache_key_contains_no_url_components():
    service = ThreatIntelService()
    key = service._get_domain_key("https://example.com/login?token=SECRET#private")
    assert key == "example.com"
    assert "/" not in key
    assert "?" not in key
    assert "#" not in key
    assert "@" not in key
    assert ":" not in key

@pytest.mark.asyncio
async def test_sensitive_values_never_reach_provider():
    provider = RecordingProvider()
    service = ThreatIntelService(provider=provider)
    await service.check_url(
        "https://alice:SECRET_PASSWORD@example.com/"
        "?token=AUTH_TOKEN_123&data=USER_PRIVATE_DATA"
        "#USER_PRIVATE_DATA"
    )
    assert len(provider.urls) == 1
    sent_value = provider.urls[0]
    assert "SECRET_PASSWORD" not in sent_value
    assert "AUTH_TOKEN_123" not in sent_value
    assert "USER_PRIVATE_DATA" not in sent_value

class SecretLeakProvider:
    @property
    def name(self):
        return "secret_leak_provider"
    async def check_url(self, url):
        raise RuntimeError("failure token=SUPER_SECRET_VALUE")

@pytest.mark.asyncio
async def test_provider_exception_does_not_escape():
    service = ThreatIntelService(provider=SecretLeakProvider())
    result = await service.check_url("https://example.com/?token=URL_SECRET")
    assert result.available is False
    assert result.is_malicious is False
