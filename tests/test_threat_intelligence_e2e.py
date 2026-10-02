import pytest
from backend.detection.engine.scorer import analyze_url_security
from backend.detection.analysis.fusion import fuse_evidence
from backend.detection.intelligence.schemas import ThreatIntelResult
from backend.detection.intelligence.service import ThreatIntelService


class EvaluationProvider:
    @property
    def name(self):
        return "evaluation_provider"

    def __init__(self, result):
        self.result = result
        self.calls = []

    async def check_url(self, domain):
        self.calls.append(domain)
        return self.result


@pytest.mark.asyncio
async def test_e2e_known_malicious_domain():
    provider = EvaluationProvider(
        ThreatIntelResult(
            available=True,
            is_malicious=True,
            confidence="high",
            source="evaluation_provider",
            reason="Known malicious domain",
        )
    )

    service = ThreatIntelService(provider=provider)
    url = "https://example.com/login?token=SECRET"

    heuristic = analyze_url_security(url)
    intelligence = await service.check_url(url)
    final = fuse_evidence(heuristic, intelligence)

    assert intelligence.available is True
    assert intelligence.is_malicious is True
    assert final.status == "DANGEROUS"
    assert final.risk_score == 100
    assert provider.calls == ["example.com"]


@pytest.mark.asyncio
async def test_e2e_clean_intelligence_preserves_heuristic():
    provider = EvaluationProvider(
        ThreatIntelResult(
            available=True,
            is_malicious=False,
            confidence="low",
            source="evaluation_provider",
            reason=None,
        )
    )

    service = ThreatIntelService(provider=provider)
    url = "https://paypal.com.attacker.com"

    heuristic = analyze_url_security(url)
    intelligence = await service.check_url(url)
    final = fuse_evidence(heuristic, intelligence)

    assert final == heuristic


@pytest.mark.asyncio
async def test_e2e_intelligence_unavailable_preserves_heuristics():
    provider = EvaluationProvider(ThreatIntelResult.unavailable())
    service = ThreatIntelService(provider=provider)
    url = "https://paypal.com.attacker.com"

    heuristic = analyze_url_security(url)
    intelligence = await service.check_url(url)
    final = fuse_evidence(heuristic, intelligence)

    assert intelligence.available is False
    assert final == heuristic


class FailingEvaluationProvider:
    @property
    def name(self):
        return "failing_evaluation_provider"

    async def check_url(self, domain):
        raise TimeoutError("temporary timeout")


@pytest.mark.asyncio
async def test_e2e_provider_failure_is_fail_safe():
    service = ThreatIntelService(provider=FailingEvaluationProvider())
    url = "https://paypal.com.attacker.com"

    heuristic = analyze_url_security(url)
    intelligence = await service.check_url(url)
    final = fuse_evidence(heuristic, intelligence)

    assert intelligence.available is False
    assert intelligence.is_malicious is False
    assert final == heuristic


@pytest.mark.asyncio
async def test_e2e_provider_receives_only_domain():
    provider = EvaluationProvider(
        ThreatIntelResult(
            available=True,
            is_malicious=False,
            confidence="low",
            source="evaluation_provider",
            reason=None,
        )
    )
    service = ThreatIntelService(provider=provider)
    url = (
        "https://username:password@example.com/"
        "private/reset"
        "?token=SUPER_SECRET"
        "#private"
    )

    await service.check_url(url)
    assert provider.calls == ["example.com"]


@pytest.mark.asyncio
async def test_e2e_cache_reuses_domain_intelligence():
    result = ThreatIntelResult(
        available=True,
        is_malicious=True,
        confidence="high",
        source="evaluation_provider",
        reason="Known threat",
    )
    provider = EvaluationProvider(result)
    service = ThreatIntelService(provider=provider)

    first_url = "https://example.com/login?token=AAA"
    second_url = "https://EXAMPLE.COM/account?token=BBB"

    first = await service.check_url(first_url)
    second = await service.check_url(second_url)

    assert first == second
    assert provider.calls == ["example.com"]


@pytest.mark.asyncio
async def test_e2e_different_domains_do_not_share_cache():
    result = ThreatIntelResult(
        available=True,
        is_malicious=False,
        confidence="low",
        source="evaluation_provider",
        reason=None,
    )
    provider = EvaluationProvider(result)
    service = ThreatIntelService(provider=provider)

    await service.check_url("https://example.com")
    await service.check_url("https://another-example.com")

    assert provider.calls == ["example.com", "another-example.com"]


@pytest.mark.asyncio
async def test_e2e_heuristic_and_intelligence_evidence_coexist():
    url = "https://paypal.com.attacker.com"
    heuristic = analyze_url_security(url)

    provider = EvaluationProvider(
        ThreatIntelResult(
            available=True,
            is_malicious=True,
            confidence="high",
            source="evaluation_provider",
            reason="Known malicious domain",
        )
    )
    service = ThreatIntelService(provider=provider)

    intelligence = await service.check_url(url)
    final = fuse_evidence(heuristic, intelligence)

    heuristic_rules = {reason.rule for reason in heuristic.reasons}
    final_rules = {reason.rule for reason in final.reasons}

    assert heuristic_rules.issubset(final_rules)
    assert "THREAT_INTELLIGENCE_MATCH" in final_rules
    assert final.status == "DANGEROUS"
    assert final.risk_score == 100


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url,is_malicious,expected_status,expected_score",
    [
        ("https://example.com", False, "SAFE", 0),
        ("https://paypal.com.attacker.com", False, "SUSPICIOUS", 46),
    ],
)
async def test_e2e_clean_intelligence_matrix(
    url,
    is_malicious,
    expected_status,
    expected_score,
):
    provider = EvaluationProvider(
        ThreatIntelResult(
            available=True,
            is_malicious=is_malicious,
            confidence="low",
            source="evaluation_provider",
            reason=None,
        )
    )
    service = ThreatIntelService(provider=provider)

    heuristic = analyze_url_security(url)
    intelligence = await service.check_url(url)
    final = fuse_evidence(heuristic, intelligence)

    assert final.status == expected_status
    assert final.risk_score == expected_score
