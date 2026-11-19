"""Tests for tier-two providers."""

import pytest

from guardrail_cascade.core import Action, CheckResult
from guardrail_cascade.providers import StubProvider, Tier2Provider


class _FlakyProvider(Tier2Provider):
    """A provider whose backend is always unreachable, for the shared path."""

    def __init__(self, fail_open: bool = False):
        self.fail_open = fail_open

    def check(self, text: str) -> CheckResult:
        return self._unavailable_result({"error": "backend_down"})


def test_stub_blocks_on_configured_keyword():
    provider = StubProvider(block_keywords=["malware"])
    result = provider.check("a guide to writing malware")
    assert result.action is Action.BLOCK
    assert result.detail["category"] == "malware"


def test_stub_matching_is_case_insensitive():
    provider = StubProvider(block_keywords=["Weapons"])
    assert provider.check("buying WEAPONS online").action is Action.BLOCK


def test_stub_allows_clean_text():
    provider = StubProvider(block_keywords=["malware"])
    assert provider.check("what is the capital of France?").action is Action.ALLOW


def test_stub_with_no_keywords_allows_everything():
    provider = StubProvider()
    assert provider.check("anything at all").action is Action.ALLOW


def test_stub_is_a_tier2_provider():
    assert isinstance(StubProvider(), Tier2Provider)


def test_tier2_provider_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        Tier2Provider()


def test_a_new_provider_inherits_the_fail_closed_default():
    result = _FlakyProvider().check("hello")
    assert result.action is Action.BLOCK
    assert "failed closed" in result.reason
    assert result.detail["error"] == "backend_down"


def test_a_new_provider_can_opt_into_failing_open():
    result = _FlakyProvider(fail_open=True).check("hello")
    assert result.action is Action.FLAG
    assert "failed open" in result.reason
