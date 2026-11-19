"""Tests for the Bedrock tier-two provider, against a fake client (no network, no AWS)."""

import pytest

botocore = pytest.importorskip("botocore")
from botocore.exceptions import ClientError, EndpointConnectionError  # noqa: E402

from guardrail_cascade.cascade import CascadePolicy, Tier  # noqa: E402
from guardrail_cascade.core import Action  # noqa: E402
from guardrail_cascade.heuristics import PIIGuard, ToxicityGuard  # noqa: E402
from guardrail_cascade.ledger import EvidenceLedger  # noqa: E402
from guardrail_cascade.providers import BedrockProvider  # noqa: E402


def intervened(assessments):
    return {"action": "GUARDRAIL_INTERVENED", "assessments": assessments}


class FakeClient:
    """Mimics ``client.apply_guardrail`` and keeps the kwargs of every call."""

    def __init__(self, reply):
        self._reply = reply
        self.calls: list[dict] = []

    def apply_guardrail(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self._reply, Exception):
            raise self._reply
        return self._reply


def connection_error():
    return EndpointConnectionError(endpoint_url="https://bedrock-runtime.us-east-1.amazonaws.com")


def client_error(code="ThrottlingException"):
    return ClientError({"Error": {"Code": code, "Message": "slow down"}}, "ApplyGuardrail")


def test_no_intervention_allows():
    provider = BedrockProvider("gr-1", client=FakeClient({"action": "NONE"}))
    assert provider.check("what were our top products?").action is Action.ALLOW


def test_intervention_blocks_with_the_content_filter_type():
    reply = intervened([{"contentPolicy": {"filters": [{"type": "VIOLENCE", "action": "BLOCKED"}]}}])
    result = BedrockProvider("gr-1", client=FakeClient(reply)).check("...")
    assert result.action is Action.BLOCK
    assert result.detail["category"] == "violence"
    assert result.reason == "tier-two guardrail intervened: violence"


def test_category_reads_topic_pii_regex_and_managed_word_labels():
    reply = intervened(
        [
            {
                "topicPolicy": {"topics": [{"name": "legal_advice", "action": "BLOCKED"}]},
                "sensitiveInformationPolicy": {
                    "piiEntities": [{"type": "EMAIL", "match": "john.doe@acme.com", "action": "BLOCKED"}],
                    "regexes": [{"name": "employee_id", "match": "E-0042", "action": "BLOCKED"}],
                },
                "wordPolicy": {"managedWordLists": [{"type": "PROFANITY", "action": "BLOCKED"}]},
            }
        ]
    )
    result = BedrockProvider("gr-1", client=FakeClient(reply)).check("...")
    assert result.detail["category"] == "legal_advice, email, employee_id, profanity"


def test_the_matched_span_never_reaches_the_category_or_detail():
    # The response echoes the offending values back in the match fields; none of
    # them may land in the ledger detail.
    reply = intervened(
        [
            {
                "sensitiveInformationPolicy": {
                    "piiEntities": [{"type": "EMAIL", "match": "john.doe@acme.com", "action": "BLOCKED"}]
                },
                "wordPolicy": {"customWords": [{"match": "hunter2", "action": "BLOCKED"}]},
            }
        ]
    )
    result = BedrockProvider("gr-1", client=FakeClient(reply)).check("...")
    assert "acme" not in result.detail["category"]
    assert "hunter2" not in result.detail["category"]
    assert result.detail["category"] == "email, custom_word"


def test_duplicate_categories_are_collapsed():
    reply = intervened(
        [
            {"contentPolicy": {"filters": [{"type": "HATE"}]}},
            {"contentPolicy": {"filters": [{"type": "HATE"}]}},
        ]
    )
    assert BedrockProvider("gr-1", client=FakeClient(reply)).check("...").detail["category"] == "hate"


def test_intervention_with_no_named_assessment_still_blocks():
    result = BedrockProvider("gr-1", client=FakeClient(intervened([]))).check("...")
    assert result.action is Action.BLOCK
    assert result.detail["category"] == "intervened"


def test_the_request_is_sent_to_the_configured_guardrail():
    client = FakeClient({"action": "NONE"})
    BedrockProvider("gr-9", guardrail_version="3", source="OUTPUT", client=client).check("hello")
    call = client.calls[0]
    assert call["guardrailIdentifier"] == "gr-9"
    assert call["guardrailVersion"] == "3"
    assert call["source"] == "OUTPUT"
    assert call["content"] == [{"text": {"text": "hello"}}]


def test_connection_error_fails_closed_by_default():
    result = BedrockProvider("gr-1", client=FakeClient(connection_error())).check("hello")
    assert result.action is Action.BLOCK
    assert result.detail["error"] == "EndpointConnectionError"


def test_client_error_fails_open_as_a_flag_when_asked():
    result = BedrockProvider("gr-1", client=FakeClient(client_error()), fail_open=True).check("hello")
    assert result.action is Action.FLAG
    assert "failed open" in result.reason


def test_an_unexpected_action_fails_closed():
    result = BedrockProvider("gr-1", client=FakeClient({"action": "SOMETHING_NEW"})).check("hello")
    assert result.action is Action.BLOCK
    assert result.detail["error"] == "unexpected_action:SOMETHING_NEW"


def test_a_bug_in_the_caller_is_not_swallowed_as_an_outage():
    with pytest.raises(TypeError):
        BedrockProvider("gr-1", client=FakeClient(TypeError("bad kwarg"))).check("hello")


def test_cascade_escalates_a_flag_and_takes_the_bedrock_verdict():
    ledger = EvidenceLedger()
    reply = intervened([{"contentPolicy": {"filters": [{"type": "HATE", "action": "BLOCKED"}]}}])
    policy = CascadePolicy(
        Tier("tier1", [PIIGuard(), ToxicityGuard()]), BedrockProvider("gr-1", client=FakeClient(reply)), ledger
    )
    decision = policy.evaluate("that racist joke was about [EMAIL]")
    assert decision.decided_by == "tier2"
    assert decision.action is Action.BLOCK
    assert ledger.entries[0]["detail"]["BedrockProvider"]["category"] == "hate"
