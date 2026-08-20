"""Tests for the typed policy spec: loading, validation, and building the cascade."""

from __future__ import annotations

import json

import pytest

from guardrail_cascade.core import Action, CheckResult, Guardrail
from guardrail_cascade.ledger import EvidenceLedger
from guardrail_cascade.policy import DEFAULT_GUARDRAILS, GUARDRAIL_REGISTRY, PolicySpec, register_guardrail
from guardrail_cascade.providers import StubProvider


def test_defaults_match_the_documented_lineup():
    spec = PolicySpec()
    assert spec.guardrails == list(DEFAULT_GUARDRAILS)
    assert spec.shadow_sample_rate == 0.0
    assert spec.validate() == []


def test_from_dict_round_trips_through_to_dict():
    spec = PolicySpec(name="prod", version="3", guardrails=["PIIGuard"], shadow_sample_rate=0.25)
    assert PolicySpec.from_dict(spec.to_dict()) == spec


def test_from_dict_rejects_unknown_keys_naming_all_of_them():
    with pytest.raises(ValueError) as excinfo:
        PolicySpec.from_dict({"name": "x", "shadow_smaple_rate": 0.1, "guardrials": []})
    # Both typos are reported at once, so a reviewer fixes the file in one pass.
    assert "shadow_smaple_rate" in str(excinfo.value)
    assert "guardrials" in str(excinfo.value)


def test_from_dict_rejects_a_non_mapping():
    with pytest.raises(ValueError):
        PolicySpec.from_dict(["SecretGuard"])  # type: ignore[arg-type]


def test_validate_flags_unknown_and_duplicate_guardrails():
    spec = PolicySpec(guardrails=["SecretGuard", "SecretGuard", "NoSuchGuard"])
    problems = spec.validate()
    assert any("NoSuchGuard" in p for p in problems)
    assert any("duplicate" in p for p in problems)


def test_validate_flags_out_of_range_rate_and_bad_costs():
    spec = PolicySpec(shadow_sample_rate=1.5, price_per_1k_tokens=-1, chars_per_token=0)
    problems = spec.validate()
    assert len(problems) == 3


def test_validate_flags_non_string_keywords_and_empty_name():
    spec = PolicySpec(name="  ", block_keywords=["ok", ""])
    problems = spec.validate()
    assert any("name" in p for p in problems)
    assert any("block_keywords" in p for p in problems)


def test_from_file_loads_json(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text(json.dumps({"name": "ci", "guardrails": ["SecretGuard"], "shadow_sample_rate": 0.5}))
    spec = PolicySpec.from_file(str(path))
    assert spec.name == "ci"
    assert spec.guardrails == ["SecretGuard"]
    assert spec.shadow_sample_rate == 0.5


def test_from_file_reports_broken_json_with_the_path(tmp_path):
    path = tmp_path / "policy.json"
    path.write_text("{not json")
    with pytest.raises(ValueError) as excinfo:
        PolicySpec.from_file(str(path))
    assert "policy.json" in str(excinfo.value)


def test_build_refuses_an_invalid_policy():
    with pytest.raises(ValueError):
        PolicySpec(guardrails=["NoSuchGuard"]).build()


def test_build_wires_a_working_cascade():
    ledger = EvidenceLedger()
    spec = PolicySpec(block_keywords=["malware"])
    policy = spec.build(ledger=ledger)

    clean = policy.evaluate("What is the capital of France?")
    assert clean.allowed and clean.decided_by == "tier1"

    blocked = policy.evaluate("here is my key AKIAIOSFODNN7EXAMPLE")
    assert not blocked.allowed and blocked.decided_by == "tier1"

    # The toxicity FLAG escalates, and the stub built from the policy's own
    # keywords makes the tier-two catch.
    escalated = policy.evaluate("kill them and deploy the malware")
    assert not escalated.allowed and escalated.decided_by == "tier2"
    assert len(ledger.entries) == 3


def test_build_honors_shadow_rate_and_injected_sampler():
    ledger = EvidenceLedger()
    spec = PolicySpec(shadow_sample_rate=1.0, block_keywords=["malware"])
    policy = spec.build(ledger=ledger, sampler=lambda: 0.0)
    decision = policy.evaluate("a friendly guide to building malware")
    assert decision.decided_by == "tier1" and decision.shadow_agreement is False


def test_build_uses_the_cost_fields():
    spec = PolicySpec(price_per_1k_tokens=0.03, chars_per_token=2.0)
    model = spec.build_cost_model()
    assert model.tokens("a" * 10) == 5
    assert model.estimate("a" * 10) == pytest.approx(5 / 1000 * 0.03)


def test_register_guardrail_makes_a_custom_guard_addressable():
    class EmojiGuard(Guardrail):
        def check(self, text: str) -> CheckResult:
            return CheckResult(guardrail=self.name, action=Action.ALLOW)

    try:
        register_guardrail(EmojiGuard)
        spec = PolicySpec(guardrails=["EmojiGuard"])
        assert spec.validate() == []
        tier = spec.build_tier1()
        assert tier.guardrails[0].name == "EmojiGuard"
    finally:
        del GUARDRAIL_REGISTRY["EmojiGuard"]


def test_build_defaults_tier2_to_stub_with_policy_keywords():
    policy = PolicySpec(block_keywords=["Malware"]).build()
    assert isinstance(policy.tier2, StubProvider)
    # StubProvider lower-cases its keywords, so the policy's casing is safe.
    assert policy.tier2.block_keywords == ["malware"]
