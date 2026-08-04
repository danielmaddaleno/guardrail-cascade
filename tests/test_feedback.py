"""Tests for the candidate-mining improvement loop."""

from guardrail_cascade.feedback import CandidateMiner, RuleProposal


def _tier2_block(category=None, request_id="r"):
    """An escalated request that tier two blocked."""
    detail = {"StubProvider": {"category": category}} if category is not None else {}
    return {"decided_by": "tier2", "allowed": False, "detail": detail, "request_id": request_id}


def _shadow_false_negative(category, request_id="r"):
    """A tier-one allow whose shadow probe disagreed."""
    return {
        "decided_by": "tier1",
        "allowed": True,
        "shadow_agreement": False,
        "shadow": {"provider": "StubProvider", "action": "BLOCK", "detail": {"category": category}},
        "request_id": request_id,
    }


def test_mine_groups_tier2_blocks_by_category():
    entries = [_tier2_block("malware", "r1"), _tier2_block("malware", "r2"), _tier2_block("weapons", "r3")]
    proposals = CandidateMiner().mine(entries)
    assert proposals[0] == RuleProposal(signal="malware", support=2, examples=["r1", "r2"])
    assert {p.signal for p in proposals} == {"malware", "weapons"}


def test_mine_ignores_tier1_blocks_and_clean_allows():
    entries = [
        {"decided_by": "tier1", "allowed": False, "request_id": "r1"},  # tier1 caught it, not a miss
        {"decided_by": "tier1", "allowed": True, "shadow_agreement": True, "request_id": "r2"},  # probe agreed
        {"decided_by": "tier1", "allowed": True, "shadow_agreement": None, "request_id": "r3"},  # not sampled
        _tier2_block("malware", "r4"),  # the only escalated miss
    ]
    proposals = CandidateMiner().mine(entries)
    assert len(proposals) == 1
    assert proposals[0].signal == "malware"


def test_shadow_false_negative_counts_as_a_miss():
    entries = [_tier2_block("malware", "r1"), _shadow_false_negative("malware", "r2")]
    proposals = CandidateMiner().mine(entries)
    assert proposals[0] == RuleProposal(signal="malware", support=2, examples=["r1", "r2"])


def test_mine_ranks_by_support_descending():
    entries = [_tier2_block("a", "r%d" % i) for i in range(3)] + [_tier2_block("b", "s%d" % i) for i in range(5)]
    proposals = CandidateMiner().mine(entries)
    assert [p.signal for p in proposals] == ["b", "a"]


def test_examples_are_capped():
    entries = [_tier2_block("a", "r%d" % i) for i in range(10)]
    proposals = CandidateMiner(max_examples=3).mine(entries)
    assert proposals[0].support == 10
    assert len(proposals[0].examples) == 3


def test_missing_category_falls_back_to_uncategorized():
    proposals = CandidateMiner().mine([_tier2_block(None, "r1")])
    assert proposals[0].signal == "uncategorized"


def test_empty_ledger_yields_no_proposals():
    assert CandidateMiner().mine([]) == []
