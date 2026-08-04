"""Tests for the evidence ledger: hash chain, tamper detection, summary."""

import json

import pytest

from guardrail_cascade.ledger import CostModel, EvidenceLedger, GENESIS_HASH


@pytest.fixture
def clock():
    """A deterministic timestamp source so entry hashes are reproducible."""
    counter = iter(range(1000))
    return lambda: "t%03d" % next(counter)


def test_first_entry_links_to_genesis(clock):
    ledger = EvidenceLedger(now=clock)
    entry = ledger.append({"action": "ALLOW", "allowed": True})
    assert entry["prev_hash"] == GENESIS_HASH
    assert len(entry["entry_hash"]) == 64


def test_entries_chain_to_each_other(clock):
    ledger = EvidenceLedger(now=clock)
    first = ledger.append({"action": "ALLOW", "allowed": True})
    second = ledger.append({"action": "BLOCK", "allowed": False})
    assert second["prev_hash"] == first["entry_hash"]
    assert ledger.verify()


def test_tampering_with_a_field_breaks_the_chain(clock):
    ledger = EvidenceLedger(now=clock)
    ledger.append({"action": "ALLOW", "allowed": True})
    ledger.append({"action": "BLOCK", "allowed": False})
    assert ledger.verify()
    # Flip a past decision without recomputing hashes.
    ledger._entries[0]["allowed"] = False
    assert not ledger.verify()


def test_removing_an_entry_breaks_the_chain(clock):
    ledger = EvidenceLedger(now=clock)
    ledger.append({"action": "ALLOW", "allowed": True})
    ledger.append({"action": "BLOCK", "allowed": False})
    ledger.append({"action": "ALLOW", "allowed": True})
    del ledger._entries[1]
    assert not ledger.verify()


def test_append_rejects_reserved_keys(clock):
    ledger = EvidenceLedger(now=clock)
    with pytest.raises(ValueError):
        ledger.append({"allowed": True, "entry_hash": "garbage"})
    with pytest.raises(ValueError):
        ledger.append({"allowed": True, "prev_hash": "garbage"})


def test_timestamp_is_stamped_when_absent(clock):
    ledger = EvidenceLedger(now=clock)
    entry = ledger.append({"action": "ALLOW", "allowed": True})
    assert entry["timestamp"] == "t000"


def test_persistence_appends_jsonl(tmp_path, clock):
    path = tmp_path / "ledger.jsonl"
    ledger = EvidenceLedger(path=str(path), now=clock)
    ledger.append({"action": "ALLOW", "allowed": True})
    ledger.append({"action": "BLOCK", "allowed": False})
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[1])["action"] == "BLOCK"


def test_summary_counts_and_rates(clock):
    ledger = EvidenceLedger(now=clock)
    ledger.append(
        {"allowed": False, "decided_by": "tier1", "latency_ms": 1.0, "cost_estimate": 0.0, "cost_saved": 0.03}
    )
    ledger.append(
        {"allowed": False, "decided_by": "tier2", "latency_ms": 5.0, "cost_estimate": 0.01, "cost_saved": 0.0}
    )
    ledger.append({"allowed": True, "decided_by": "tier2", "latency_ms": 3.0, "cost_estimate": 0.01, "cost_saved": 0.0})
    summary = ledger.summary()
    assert summary.total == 3
    assert summary.allowed == 1
    assert summary.blocked_by_tier1 == 1
    assert summary.blocked_by_tier2 == 1
    assert summary.decided_by_tier1 == 1  # the one tier-one block; the two tier-two entries are not
    assert summary.tier1_block_rate == pytest.approx(1 / 3)
    assert summary.short_circuit_rate == pytest.approx(1 / 3)
    assert summary.cost_saved == pytest.approx(0.03)
    assert summary.cost_incurred == pytest.approx(0.02)


def test_summary_of_empty_ledger_is_zeroed():
    summary = EvidenceLedger().summary()
    assert summary.total == 0
    assert summary.tier1_block_rate == 0.0
    assert summary.short_circuit_rate == 0.0
    assert summary.latency_p50_ms == 0.0


def test_cost_model_estimate_scales_with_length():
    model = CostModel(price_per_1k_tokens=0.003, chars_per_token=4.0)
    assert model.tokens("a" * 40) == 10
    assert model.estimate("a" * 40) == pytest.approx(10 / 1000 * 0.003)
    assert model.estimate("") == 0.0
