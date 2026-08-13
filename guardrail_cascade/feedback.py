"""The improvement loop: let tier two teach tier one, safely.

Two kinds of ledger entry say tier one should have done better:

- an escalated request that tier two blocked (tier one only flagged or redacted
  it), and
- a short-circuited allow whose shadow probe disagreed, meaning tier two would
  have blocked something tier one waved through.

Both are mined into rule proposals for a human to review. This does not edit any
rule by itself: synthesizing a regex from examples overfits and risks
catastrophic backtracking (ReDoS), so a person stays in the loop.

Selection bias, and why the shadow signal matters. Tier two only ever sees the
traffic tier one escalated, so escalated catches alone describe misses among the
flagged band, not the true distribution. The shadow-sampled allows are the one
source of labels on traffic tier one let straight through, so folding them in is
what keeps the proposals from only ever learning about already-suspicious text.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class RuleProposal:
    """A candidate tier-one rule, awaiting human review. Never auto-applied."""

    signal: str
    support: int
    examples: list[str] = field(default_factory=list)


def _category(entry: dict) -> str:
    """Pull the tier-two category out of an entry's detail or shadow record.

    A missing category, and an explicit null or empty one, both fall back to
    "uncategorized" so a provider that reports ``{"category": None}`` does not
    open a stray "None" bucket alongside the real ones.
    """
    sources = list(entry.get("detail", {}).values())
    shadow = entry.get("shadow")
    if isinstance(shadow, dict) and isinstance(shadow.get("detail"), dict):
        sources.append(shadow["detail"])
    for value in sources:
        if isinstance(value, dict) and value.get("category"):
            return str(value["category"])
    return "uncategorized"


def _is_tier1_miss(entry: dict) -> bool:
    escalated_catch = entry.get("decided_by") == "tier2" and not entry.get("allowed")
    shadow_false_negative = (
        entry.get("decided_by") == "tier1" and entry.get("allowed") and entry.get("shadow_agreement") is False
    )
    return bool(escalated_catch or shadow_false_negative)


class CandidateMiner:
    """Turn tier-one misses into reviewable tier-one rule proposals."""

    def __init__(self, max_examples: int = 5):
        self.max_examples = max_examples

    def mine(self, entries: list[dict]) -> list[RuleProposal]:
        """Group misses by tier-two category and rank them by support.

        A ledger entry counts as a miss when tier two blocked an escalated
        request, or when a shadow probe disagreed with a tier-one allow. Entries
        without a reported category fall under ``"uncategorized"``.
        """
        support: dict[str, int] = defaultdict(int)
        examples: dict[str, list[str]] = defaultdict(list)

        for entry in entries:
            if not _is_tier1_miss(entry):
                continue
            category = _category(entry)
            support[category] += 1
            request_id = entry.get("request_id")
            if request_id and len(examples[category]) < self.max_examples:
                examples[category].append(request_id)

        proposals = [
            RuleProposal(signal=category, support=count, examples=examples[category])
            for category, count in support.items()
        ]
        proposals.sort(key=lambda p: p.support, reverse=True)
        return proposals
