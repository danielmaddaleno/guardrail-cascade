"""Evidence ledger: an append-only, hash-chained record of every decision.

Each entry is hash-chained to the one before it: ``entry_hash`` is the SHA-256
of ``prev_hash`` concatenated with the canonical JSON of the entry fields. Any
edit to a past field, or a removed line, breaks the chain and :meth:`verify`
returns ``False``. That detects accidental or partial edits; it does not stop an
attacker with full read and write access, who could rewrite an entry and
recompute every later hash forward, since the chain has no external anchor yet
(see the roadmap). Because the same entries also carry token counts, latency and
cost, the ledger doubles as the observability and FinOps surface.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

GENESIS_HASH = "0" * 64


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class CostModel:
    """A minimal price model for estimating and saving tier-two spend.

    Tokens are approximated from character length (about four characters per
    token), the same cheap heuristic the guardrails toolkit uses, so no
    tokenizer dependency is pulled in. ``price_per_1k_tokens`` is the tier-two
    provider's blended input price.
    """

    price_per_1k_tokens: float = 0.003
    chars_per_token: float = 4.0

    def tokens(self, text: str) -> int:
        return math.ceil(len(text) / self.chars_per_token)

    def estimate(self, text: str) -> float:
        return self.tokens(text) / 1000.0 * self.price_per_1k_tokens


@dataclass
class LedgerSummary:
    """Aggregate view over the ledger, ready to print on a dashboard."""

    total: int
    allowed: int
    blocked_by_tier1: int
    blocked_by_tier2: int
    decided_by_tier1: int
    tier1_block_rate: float
    short_circuit_rate: float
    cost_incurred: float
    cost_saved: float
    latency_p50_ms: float
    latency_p95_ms: float


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    # Nearest-rank percentile: simple and dependency-free.
    rank = max(0, math.ceil(pct / 100.0 * len(ordered)) - 1)
    return ordered[rank]


class EvidenceLedger:
    """Append-only, hash-chained log of cascade decisions.

    Entries are kept in memory and, when ``path`` is given, also appended to a
    JSON Lines file so the chain survives a restart. ``now`` is injectable so
    tests get deterministic timestamps.
    """

    def __init__(self, path: str | None = None, now: Callable[[], str] = _utc_now_iso):
        self.path = path
        self._now = now
        self._entries: list[dict] = []

    @staticmethod
    def _canonical(fields: dict) -> str:
        return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @classmethod
    def _hash(cls, prev_hash: str, fields: dict) -> str:
        payload = (prev_hash + cls._canonical(fields)).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def append(self, fields: dict) -> dict:
        """Add ``fields`` as the next chained entry and return the full record.

        A ``timestamp`` is stamped in if the caller did not supply one. The
        stored record is ``fields`` plus ``prev_hash`` and ``entry_hash``. Those
        two keys are reserved: passing them in ``fields`` is rejected, otherwise
        an entry could be born already failing :meth:`verify`.
        """
        for reserved in ("prev_hash", "entry_hash"):
            if reserved in fields:
                raise ValueError("%r is a reserved ledger key and cannot be supplied by the caller" % reserved)
        record = dict(fields)
        record.setdefault("timestamp", self._now())
        prev_hash = self._entries[-1]["entry_hash"] if self._entries else GENESIS_HASH
        entry_hash = self._hash(prev_hash, record)
        record["prev_hash"] = prev_hash
        record["entry_hash"] = entry_hash
        self._entries.append(record)
        if self.path is not None:
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        return record

    @property
    def entries(self) -> list[dict]:
        return list(self._entries)

    def verify(self) -> bool:
        """Return True if the whole chain recomputes and links correctly."""
        prev_hash = GENESIS_HASH
        for record in self._entries:
            fields = {k: v for k, v in record.items() if k not in ("prev_hash", "entry_hash")}
            if record["prev_hash"] != prev_hash:
                return False
            if record["entry_hash"] != self._hash(prev_hash, fields):
                return False
            prev_hash = record["entry_hash"]
        return True

    def summary(self) -> LedgerSummary:
        total = len(self._entries)
        allowed = sum(1 for e in self._entries if e.get("allowed"))
        blocked_t1 = sum(1 for e in self._entries if not e.get("allowed") and e.get("decided_by") == "tier1")
        blocked_t2 = sum(1 for e in self._entries if not e.get("allowed") and e.get("decided_by") == "tier2")
        # A short-circuit is any request tier one decided on its own (allow or
        # block), which is what actually skips the paid tier.
        decided_t1 = sum(1 for e in self._entries if e.get("decided_by") == "tier1")
        latencies = [float(e.get("latency_ms", 0.0)) for e in self._entries]
        return LedgerSummary(
            total=total,
            allowed=allowed,
            blocked_by_tier1=blocked_t1,
            blocked_by_tier2=blocked_t2,
            decided_by_tier1=decided_t1,
            tier1_block_rate=(blocked_t1 / total if total else 0.0),
            short_circuit_rate=(decided_t1 / total if total else 0.0),
            cost_incurred=sum(float(e.get("cost_estimate", 0.0)) for e in self._entries),
            cost_saved=sum(float(e.get("cost_saved", 0.0)) for e in self._entries),
            latency_p50_ms=_percentile(latencies, 50),
            latency_p95_ms=_percentile(latencies, 95),
        )
