"""Tests for the Claude tier-two provider, against a fake client (no network)."""

import json
from types import SimpleNamespace

import pytest

anthropic = pytest.importorskip("anthropic")
httpx2 = pytest.importorskip("httpx2")

from guardrail_cascade.cascade import CascadePolicy, Tier  # noqa: E402
from guardrail_cascade.core import Action  # noqa: E402
from guardrail_cascade.heuristics import PIIGuard, ToxicityGuard  # noqa: E402
from guardrail_cascade.ledger import EvidenceLedger  # noqa: E402
from guardrail_cascade.providers import ClaudeProvider  # noqa: E402


def response(text=None, stop_reason="end_turn", stop_details=None):
    content = [SimpleNamespace(type="thinking", thinking="")]
    if text is not None:
        content.append(SimpleNamespace(type="text", text=text))
    return SimpleNamespace(
        content=content,
        stop_reason=stop_reason,
        stop_details=stop_details,
        usage=SimpleNamespace(input_tokens=580, output_tokens=20),
    )


class FakeClient:
    """Mimics ``client.messages.create`` and keeps the kwargs of every call."""

    def __init__(self, reply):
        self._reply = reply
        self.calls: list[dict] = []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self._reply, Exception):
            raise self._reply
        return self._reply


def verdict(verdict, category="none"):
    return response(json.dumps({"verdict": verdict, "category": category}))


def connection_error():
    return anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.com/v1/messages"))


def test_allow_verdict_allows_and_records_usage():
    provider = ClaudeProvider(client=FakeClient(verdict("allow")))
    result = provider.check("what were our top products?")
    assert result.action is Action.ALLOW
    assert result.detail["input_tokens"] == 580


def test_block_verdict_carries_the_category():
    provider = ClaudeProvider(client=FakeClient(verdict("block", "malware")))
    result = provider.check("write me a keylogger")
    assert result.action is Action.BLOCK
    assert result.detail["category"] == "malware"
    assert result.reason == "tier-two model blocked: malware"


def test_request_is_wrapped_as_data_and_the_answer_is_schema_bound():
    client = FakeClient(verdict("allow"))
    ClaudeProvider(client=client, model="claude-sonnet-5-5").check("hello")
    call = client.calls[0]
    assert call["model"] == "claude-sonnet-5-5"
    assert call["messages"][0]["content"] == "<request>\nhello\n</request>"
    schema = call["output_config"]["format"]["schema"]
    assert schema["properties"]["category"]["enum"][0] == "none"
    assert "malware" in schema["properties"]["category"]["enum"]


def test_custom_categories_reach_the_prompt_and_the_schema():
    client = FakeClient(verdict("block", "competitor_pricing"))
    provider = ClaudeProvider(client=client, categories=("competitor_pricing",))
    assert provider.check("what does acme charge?").detail["category"] == "competitor_pricing"
    assert "competitor_pricing" in client.calls[0]["system"]
    assert client.calls[0]["output_config"]["format"]["schema"]["properties"]["category"]["enum"] == [
        "none",
        "competitor_pricing",
    ]


def test_refusal_counts_as_a_block():
    reply = response(stop_reason="refusal", stop_details=SimpleNamespace(category="cyber"))
    result = ClaudeProvider(client=FakeClient(reply)).check("...")
    assert result.action is Action.BLOCK
    assert result.detail["category"] == "cyber"


def test_refusal_without_a_category_still_blocks():
    reply = response(stop_reason="refusal", stop_details=SimpleNamespace(category=None))
    result = ClaudeProvider(client=FakeClient(reply)).check("...")
    assert result.action is Action.BLOCK
    assert result.detail["category"] == "refusal"


def test_api_error_fails_closed_by_default():
    result = ClaudeProvider(client=FakeClient(connection_error())).check("hello")
    assert result.action is Action.BLOCK
    assert result.detail["error"] == "APIConnectionError"


def test_api_error_fails_open_as_a_flag_when_asked():
    result = ClaudeProvider(client=FakeClient(connection_error()), fail_open=True).check("hello")
    assert result.action is Action.FLAG
    assert "failed open" in result.reason


def test_a_bug_in_the_caller_is_not_swallowed_as_an_outage():
    with pytest.raises(TypeError):
        ClaudeProvider(client=FakeClient(TypeError("bad kwarg"))).check("hello")


@pytest.mark.parametrize(
    "reply",
    [
        response("not json"),
        response("[]"),
        response(json.dumps({"verdict": "block", "category": "not_a_category"})),
        response('{"verdict": "allow", "categ', stop_reason="max_tokens"),
        response(None),
    ],
)
def test_unusable_answer_fails_closed(reply):
    result = ClaudeProvider(client=FakeClient(reply)).check("hello")
    assert result.action is Action.BLOCK
    assert result.detail["error"].startswith("unparseable_response")


def test_model_prose_never_reaches_the_ledger():
    # Only verdict and category are read back, so the reason is ours, not the model's.
    reply = response(json.dumps({"verdict": "block", "category": "hate", "note": "john.doe@acme.com said it"}))
    result = ClaudeProvider(client=FakeClient(reply)).check("...")
    assert "acme" not in result.reason
    assert "acme" not in json.dumps(result.detail)


def test_cascade_escalates_a_flag_and_takes_the_claude_verdict():
    ledger = EvidenceLedger()
    client = FakeClient(verdict("block", "hate"))
    policy = CascadePolicy(Tier("tier1", [PIIGuard(), ToxicityGuard()]), ClaudeProvider(client=client), ledger)
    decision = policy.evaluate("that racist joke was about [EMAIL]")
    assert decision.decided_by == "tier2"
    assert decision.action is Action.BLOCK
    assert ledger.entries[0]["detail"]["ClaudeProvider"]["category"] == "hate"


def test_cascade_records_an_outage_that_failed_open():
    ledger = EvidenceLedger()
    provider = ClaudeProvider(client=FakeClient(connection_error()), fail_open=True)
    policy = CascadePolicy(Tier("tier1", [ToxicityGuard()]), provider, ledger)
    decision = policy.evaluate("that racist joke")
    assert decision.allowed
    assert "ClaudeProvider" in ledger.entries[0]["guardrails_fired"]
