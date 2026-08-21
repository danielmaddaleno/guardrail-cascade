"""Evidence ledger: an append-only, hash-chained record of every decision.

Each entry is hash-chained to the one before it: ``entry_hash`` is the SHA-256
of ``prev_hash`` concatenated with the canonical JSON of the entry fields. Any
edit to a past field, or a removed line, breaks the chain and :meth:`verify`
returns ``False``. That detects accidental or partial edits; it does not stop an
attacker with full read and write access, who could rewrite an entry and
recompute every later hash forward, since the chain has no external anchor yet
(see the roadmap). Because the same entries also carry token counts, latency and
cost, the ledger doubles as the observability and FinOps surface.

Appends are serialized with a lock, so several threads of one service can write
to the same ledger and still produce a chain that verifies.

Every entry is scrubbed before it is hashed and stored (see
:mod:`guardrail_cascade.scrub`), so PII and secret-shaped values never land in
the audit log even if a caller leaves one in a field.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from guardrail_cascade.scrub import scrub

GENESIS_HASH = "0" * 64


def _read_entries(path: str) -> list[dict]:
    """Read a JSON Lines ledger file back into its records, verbatim."""
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


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
    # Shadow sampling is the audit on tier one's short-circuits, so its
    # agreement rate is the drift signal a governance review asks for. The rate
    # is over probes actually sent, not over all requests, and is 0.0 when no
    # probe ran (check ``shadow_probes`` to tell "no data" from "no agreement").
    shadow_probes: int = 0
    shadow_agreements: int = 0
    shadow_agreement_rate: float = 0.0


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
    JSON Lines file so the chain survives a restart. If that file already
    exists, its entries are read back at construction time and the next
    :meth:`append` continues their chain instead of restarting from the genesis
    hash. ``now`` is injectable so tests get deterministic timestamps.

    :meth:`append` reads the previous hash, links to it and writes the line
    under a lock, so callers on different threads of one service produce a
    chain that still verifies. The lock does not coordinate separate processes
    writing the same file; one ledger object per file is the assumption.
    """

    def __init__(
        self,
        path: str | None = None,
        now: Callable[[], str] = _utc_now_iso,
        scrubber: Callable[[dict], dict] | None = scrub,
    ):
        self.path = path
        self._now = now
        # Applied to every entry before it is hashed and stored, so a raw value
        # a caller left in a field never reaches the log. Pass None to disable.
        self._scrubber = scrubber
        self._entries: list[dict] = []
        self._lock = threading.Lock()
        if path is not None and os.path.exists(path):
            # Resume the chain already on disk. Appending to an existing file
            # from the genesis hash would leave the whole file unverifiable.
            self._entries = _read_entries(path)

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
        stored record is ``fields`` (after scrubbing) plus ``prev_hash`` and
        ``entry_hash``. Those two keys are reserved: passing them in ``fields``
        is rejected, otherwise an entry could be born already failing
        :meth:`verify`. The scrubber masks PII and secret-shaped substrings in
        every string field before the entry is hashed, so a raw value a caller
        left in ``reason`` or ``detail`` never lands in the log.
        """
        for reserved in ("prev_hash", "entry_hash"):
            if reserved in fields:
                raise ValueError("%r is a reserved ledger key and cannot be supplied by the caller" % reserved)
        record = dict(fields)
        record.setdefault("timestamp", self._now())
        if self._scrubber is not None:
            record = self._scrubber(record)
        # Reading the previous hash, linking to it and writing the line have to
        # be one step: two threads that read the same previous hash would each
        # claim the same position and leave the chain unverifiable.
        with self._lock:
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

    @classmethod
    def load(cls, path: str) -> "EvidenceLedger":
        """Load a ledger previously written to a JSON Lines file.

        Each line is restored verbatim, including its ``prev_hash`` and
        ``entry_hash``, so :meth:`verify` checks the chain as it was written,
        :meth:`summary` aggregates it, and a later :meth:`append` extends it.
        Loaded records are not re-scrubbed: they were scrubbed when first
        appended, and scrubbing them again would change their bytes and break
        the chain. A missing file is an error here, unlike in the constructor,
        where it just means nothing has been written yet.
        """
        if not os.path.exists(path):
            raise FileNotFoundError("ledger file not found: %s" % path)
        return cls(path=path)

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
        # A probe happened wherever agreement was recorded at all; True/False is
        # the verdict, None (or the key missing) means no probe was sent.
        probes = sum(1 for e in self._entries if e.get("shadow_agreement") is not None)
        agreements = sum(1 for e in self._entries if e.get("shadow_agreement") is True)
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
            shadow_probes=probes,
            shadow_agreements=agreements,
            shadow_agreement_rate=(agreements / probes if probes else 0.0),
        )
