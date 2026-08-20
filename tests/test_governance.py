"""Tests for the governance layer: control assessment, the lint gate, the system card."""

from __future__ import annotations

import pytest

from guardrail_cascade.governance import (
    CONTROL_CATALOG,
    assess_controls,
    lint_policy,
    system_card,
)
from guardrail_cascade.ledger import EvidenceLedger
from guardrail_cascade.policy import PolicySpec


def full_policy() -> PolicySpec:
    """A policy that satisfies every cataloged control."""
    return PolicySpec(name="prod", version="2", shadow_sample_rate=0.1, block_keywords=["malware"])


def by_id(assessments):
    return {a.control.control_id: a for a in assessments}


def test_catalog_ids_are_unique_and_fully_crosswalked():
    ids = [c.control_id for c in CONTROL_CATALOG]
    assert len(ids) == len(set(ids))
    for control in CONTROL_CATALOG:
        frameworks = {ref.framework for ref in control.references}
        # Every control speaks all three reviewers' languages.
        assert frameworks == {"NIST AI RMF", "ISO/IEC 42001", "EU AI Act"}


def test_full_policy_satisfies_every_control():
    assessments = assess_controls(full_policy())
    assert all(a.satisfied for a in assessments)
    assert len(assessments) == len(CONTROL_CATALOG)


def test_dropping_pii_guard_fails_only_that_control():
    spec = full_policy()
    spec.guardrails = ["SecretGuard", "PromptInjectionGuard", "ToxicityGuard"]
    assessments = by_id(assess_controls(spec))
    assert not assessments["pii-redaction"].satisfied
    assert assessments["secret-containment"].satisfied
    assert assessments["input-screening"].satisfied


def test_zero_shadow_rate_fails_drift_monitoring():
    spec = full_policy()
    spec.shadow_sample_rate = 0.0
    assessments = by_id(assess_controls(spec))
    assert not assessments["drift-monitoring"].satisfied


def test_empty_guardrail_list_fails_screening_and_the_named_guards():
    spec = full_policy()
    spec.guardrails = []
    assessments = by_id(assess_controls(spec))
    assert not assessments["input-screening"].satisfied
    assert not assessments["secret-containment"].satisfied
    assert not assessments["pii-redaction"].satisfied


def test_ledger_evidence_lands_in_the_assessment():
    spec = full_policy()
    ledger = EvidenceLedger()
    policy = spec.build(ledger=ledger, sampler=lambda: 0.0)
    policy.evaluate("here is my key AKIAIOSFODNN7EXAMPLE")
    policy.evaluate("What were our top products?")

    assessments = by_id(assess_controls(spec, ledger))
    assert "fired on 1 recorded request(s)" in assessments["secret-containment"].evidence
    assert "2 entries" in assessments["audit-trail"].evidence
    # The clean allow was shadow-probed (rate 0.1, sampler always 0.0).
    assert "agreement" in assessments["drift-monitoring"].evidence


def test_a_tampered_ledger_fails_the_audit_trail_control():
    spec = full_policy()
    ledger = EvidenceLedger()
    spec.build(ledger=ledger).evaluate("a harmless question")
    ledger._entries[0]["allowed"] = False  # break the chain
    assessments = by_id(assess_controls(spec, ledger))
    assert not assessments["audit-trail"].satisfied


def test_lint_passes_a_full_policy():
    assert lint_policy(full_policy()) == []


def test_lint_reports_spec_problems_and_stops_there():
    spec = full_policy()
    spec.shadow_sample_rate = 5.0
    problems = lint_policy(spec)
    assert any("shadow_sample_rate" in p for p in problems)
    # Control noise is not piled on top of the real spec problem.
    assert not any("required control" in p for p in problems)


def test_lint_fails_a_missing_required_control():
    spec = full_policy()
    spec.shadow_sample_rate = 0.0
    problems = lint_policy(spec)
    assert any("drift-monitoring" in p for p in problems)


def test_lint_with_a_narrowed_requirement_accepts_the_gap():
    spec = full_policy()
    spec.shadow_sample_rate = 0.0
    assert lint_policy(spec, required=["input-screening", "audit-trail"]) == []


def test_lint_rejects_an_unknown_required_control():
    problems = lint_policy(full_policy(), required=["no-such-control"])
    assert any("no-such-control" in p for p in problems)


def test_system_card_is_deterministic_and_names_every_control():
    card = system_card(full_policy(), now=lambda: "2026-01-01T00:00:00+00:00")
    assert card == system_card(full_policy(), now=lambda: "2026-01-01T00:00:00+00:00")
    assert "# System card: prod (policy v2)" in card
    for control in CONTROL_CATALOG:
        assert control.control_id in card
    # The crosswalk speaks all three frameworks and stays honest about itself.
    assert "NIST AI RMF" in card and "ISO/IEC 42001" in card and "EU AI Act" in card
    assert "not a certification" in card


def test_system_card_without_ledger_says_design_time():
    card = system_card(full_policy())
    assert "design-time card" in card


def test_system_card_with_ledger_reports_evidence_and_gaps():
    spec = full_policy()
    spec.shadow_sample_rate = 0.0
    ledger = EvidenceLedger()
    policy = spec.build(ledger=ledger)
    policy.evaluate("here is my key AKIAIOSFODNN7EXAMPLE")
    policy.evaluate("What were our top products?")

    card = system_card(spec, ledger)
    assert "| Requests recorded | 2 |" in card
    assert "| Ledger chain verifies | True |" in card
    assert "**NOT SATISFIED**" in card  # drift-monitoring, honestly reported
    assert "no probes recorded" in card


def test_system_card_escapes_markdown_table_breakers_in_policy_fields():
    spec = full_policy()
    spec.name = "prod | extra\ncolumn"
    spec.block_keywords = ["mal|ware"]
    card = system_card(spec)
    # A pipe or newline in an author-controlled field must not reshape the
    # tables of the one artifact meant to be published onward.
    assert "prod \\| extra column" in card
    assert "mal\\|ware" in card


def test_system_card_never_contains_raw_pii_from_traffic():
    spec = full_policy()
    ledger = EvidenceLedger()
    policy = spec.build(ledger=ledger)
    policy.evaluate("Summarize the account for john.doe@acme.com")
    card = system_card(spec, ledger)
    assert "john.doe@acme.com" not in card


def test_summary_shadow_metrics_feed_the_rate():
    ledger = EvidenceLedger()
    ledger.append({"allowed": True, "decided_by": "tier1", "shadow_agreement": True})
    ledger.append({"allowed": True, "decided_by": "tier1", "shadow_agreement": False})
    ledger.append({"allowed": True, "decided_by": "tier1", "shadow_agreement": None})
    summary = ledger.summary()
    assert summary.shadow_probes == 2
    assert summary.shadow_agreements == 1
    assert summary.shadow_agreement_rate == pytest.approx(0.5)
