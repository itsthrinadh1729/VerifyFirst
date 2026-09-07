"""Tests for Threat Intelligence and Reputation Layer."""

import pytest
from unittest.mock import patch, MagicMock

from backend.detection.intelligence.schemas import ThreatIntelResult
from backend.detection.intelligence.providers import GoogleSafeBrowsingProvider
from backend.detection.intelligence.service import ThreatIntelService
import httpx

@pytest.mark.asyncio
async def test_gsb_provider_privacy_stripping():
    """Verify that the provider properly strips paths and queries."""
    provider = GoogleSafeBrowsingProvider(api_key="test")
    
    url_with_path = "https://example.com/login?token=123#frag"
    safe_url = provider._get_privacy_preserving_domain_url(url_with_path)
    assert safe_url == "https://example.com/"
    
    # Check robust handling of malformed URLs
    assert provider._get_privacy_preserving_domain_url("not-a-url") == "not-a-url"

@pytest.mark.asyncio
async def test_gsb_provider_unavailable_without_api_key():
    """Verify provider returns unavailable if no API key is provided."""
    provider = GoogleSafeBrowsingProvider(api_key=None)
    result = await provider.check_url("https://example.com")
    assert not result.available
    assert not result.is_malicious

@pytest.mark.asyncio
@patch("backend.detection.intelligence.providers.httpx.AsyncClient.post")
async def test_gsb_provider_match(mock_post):
    """Verify provider returns a match correctly."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "matches": [
            {
                "threatType": "MALWARE",
                "platformType": "ANY_PLATFORM",
                "threatEntryType": "URL",
                "threat": {"url": "https://example.com/"}
            }
        ]
    }
    mock_post.return_value = mock_response

    provider = GoogleSafeBrowsingProvider(api_key="test_key")
    result = await provider.check_url("https://example.com/malicious")
    
    assert result.available
    assert result.is_malicious
    assert result.source == "Google Safe Browsing"

@pytest.mark.asyncio
@patch("backend.detection.intelligence.providers.httpx.AsyncClient.post")
async def test_gsb_provider_no_match(mock_post):
    """Verify provider handles no match correctly."""
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {}  # Empty response means no matches
    mock_post.return_value = mock_response

    provider = GoogleSafeBrowsingProvider(api_key="test_key")
    result = await provider.check_url("https://apple.com")
    
    assert result.available
    assert not result.is_malicious

@pytest.mark.asyncio
@patch("backend.detection.intelligence.providers.httpx.AsyncClient.post")
async def test_gsb_provider_timeout(mock_post):
    """Verify provider handles timeouts safely without crashing."""
    mock_post.side_effect = httpx.TimeoutException("Timeout")

    provider = GoogleSafeBrowsingProvider(api_key="test_key")
    result = await provider.check_url("https://example.com")
    
    assert not result.available
    assert not result.is_malicious
