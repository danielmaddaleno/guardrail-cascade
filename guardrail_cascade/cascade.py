"""The cascade: let the cheap tier dispose of the confident cases, pay only for the rest.

Flow for one request:

1. Run tier one (the heuristics).
2. If tier one is confident (ALLOW or BLOCK), decide right there and skip the
   paid tier. Optionally shadow-sample a fraction of these short-circuits to
   tier two so we can measure the errors they hide: false positives on a block
   and false negatives on an allow. A shadow probe is a real tier-two call, so
   it is billed and it never changes the decision, only measures it. It carries
   whatever redactions tier one applied, so masking is not undone for an audit.
3. If tier one is unsure (FLAG or REDACT), escalate to tier two, the paid
   provider, and take its verdict. This is the ambiguous middle band that
   actually warrants the expensive check.
4. Either way, write one entry to the evidence ledger with the action, which
   tier decided, latency, token estimate, and the cost incurred or saved.

Cost saved is the tier-two spend a short-circuit avoided. Summed over the
ledger, that is the number the design is meant to move. Because ALLOW and BLOCK
both short-circuit, tier two is paid only for the flagged and redacted band plus
whatever fraction of confident traffic is shadow-sampled for audit.
"""

from __future__ import annotations

import random
import time
import uuid
from dataclasses import dataclass
from typing import Callable

from guardrail_cascade.core import Action, CheckResult, Guardrail
from guardrail_cascade.ledger import CostModel, EvidenceLedger
from guardrail_cascade.providers import Tier2Provider


@dataclass
class TierResult:
    """What a tier concluded after running all of its guardrails."""

    tier: str
    action: Action
    output: str | None
    results: list[CheckResult]
    # The running text after every redaction the tier applied. Unlike ``output``
    # it survives a block, so an audit path that still wants the text has a
    # masked copy to use instead of the raw request.
    masked: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action == Action.BLOCK

    def fired(self) -> list[str]:
        """Names of the guardrails that returned anything other than ALLOW."""
        return [r.guardrail for r in self.results if r.action != Action.ALLOW]


class Tier:
    """A named, ordered collection of guardrails run as one stage.

    Guardrails run in order against the running (possibly already redacted)
    text, so a later redactor sees earlier redactions. The tier BLOCKs if any
    guardrail blocks; otherwise its action is the most severe one seen, and the
    forwarded text carries every redaction applied along the way.
    """

    def __init__(self, name: str, guardrails: list[Guardrail]):
        self.name = name
        self.guardrails = guardrails

    def run(self, text: str) -> TierResult:
        output = text
        results: list[CheckResult] = []
        highest = Action.ALLOW
        blocked = False
        for guardrail in self.guardrails:
            result = guardrail.check(output)
            results.append(result)
            highest = max(highest, result.action)
            if result.action == Action.REDACT and result.output is not None:
                output = result.output
            if result.action == Action.BLOCK:
                blocked = True
        action = Action.BLOCK if blocked else highest
        return TierResult(
            tier=self.name, action=action, output=(None if blocked else output), results=results, masked=output
        )


@dataclass
class Decision:
    """The final outcome for one request, plus everything worth auditing."""

    allowed: bool
    action: Action
    decided_by: str
    output: str | None
    reason: str
    latency_ms: float
    cost_estimate: float
    cost_saved: float
    request_id: str
    tier1_result: TierResult
    tier2_result: CheckResult | None = None
    shadow_agreement: bool | None = None


def _combined_reason(tier1: TierResult, probe: CheckResult | None) -> str:
    parts = [r.reason for r in tier1.results if r.action != Action.ALLOW and r.reason]
    if probe is not None and probe.action != Action.ALLOW and probe.reason:
        parts.append(probe.reason)
    return "; ".join(parts)


class CascadePolicy:
    """Orchestrates tier one, tier two, and the evidence ledger.

    ``sampler`` and ``clock`` are injected so tests are deterministic:
    ``sampler`` returns a float in ``[0, 1)`` and drives shadow sampling, and
    ``clock`` returns seconds for latency measurement.
    """

    def __init__(
        self,
        tier1: Tier,
        tier2: Tier2Provider,
        ledger: EvidenceLedger,
        *,
        cost_model: CostModel | None = None,
        shadow_sample_rate: float = 0.0,
        sampler: Callable[[], float] = random.random,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.tier1 = tier1
        self.tier2 = tier2
        self.ledger = ledger
        self.cost_model = cost_model or CostModel()
        self.shadow_sample_rate = shadow_sample_rate
        self._sampler = sampler
        self._clock = clock

    def _should_shadow(self) -> bool:
        if self.shadow_sample_rate <= 0.0:
            return False
        return self._sampler() < self.shadow_sample_rate

    def evaluate(self, text: str, *, request_id: str | None = None) -> Decision:
        request_id = request_id or uuid.uuid4().hex
        start = self._clock()
        tr1 = self.tier1.run(text)

        if tr1.action in (Action.ALLOW, Action.BLOCK):
            decision = self._short_circuit(text, tr1, request_id, start)
        else:
            decision = self._escalate(text, tr1, request_id, start)

        self._record(text, decision)
        return decision

    def _short_circuit(self, text: str, tr1: TierResult, request_id: str, start: float) -> Decision:
        """Decide with tier one alone, optionally shadow-probing tier two to audit it."""
        allowed = tr1.action == Action.ALLOW
        probe: CheckResult | None = None
        shadow_agreement: bool | None = None
        # Never forward a sensitive block (a matched secret) to the paid tier,
        # even for audit: the whole point of the block is to stop it propagating.
        sensitive = any(r.sensitive for r in tr1.results)
        if self._should_shadow() and not sensitive:
            # Probe with the redacted text. A block can still carry PII that a
            # redactor already masked, and the probe must not undo that.
            probe = self.tier2.check(tr1.masked if tr1.masked is not None else text)
            # Agreement means tier two would have reached the same call: block a
            # block, or leave an allow untouched. Any other verdict on an allow
            # (a REDACT or FLAG) counts as disagreement, a caught tier-one miss.
            if tr1.action == Action.BLOCK:
                shadow_agreement = probe.action == Action.BLOCK
            else:
                shadow_agreement = probe.action == Action.ALLOW

        latency_ms = (self._clock() - start) * 1000.0
        shadowed = probe is not None
        estimate = self.cost_model.estimate(text)
        return Decision(
            allowed=allowed,
            action=tr1.action,
            decided_by="tier1",
            output=(tr1.output if allowed else None),
            reason=_combined_reason(tr1, None),
            latency_ms=latency_ms,
            # A shadow probe is a real tier-two call, so it costs money and does
            # not save any. Only an unshadowed short-circuit avoids the spend.
            cost_estimate=(estimate if shadowed else 0.0),
            cost_saved=(0.0 if shadowed else estimate),
            request_id=request_id,
            tier1_result=tr1,
            tier2_result=probe,
            shadow_agreement=shadow_agreement,
        )

    def _escalate(self, text: str, tr1: TierResult, request_id: str, start: float) -> Decision:
        """Send the flagged or redacted text to tier two and take its verdict."""
        forwarded = tr1.output if tr1.output is not None else text
        probe = self.tier2.check(forwarded)
        latency_ms = (self._clock() - start) * 1000.0
        cost = self.cost_model.estimate(forwarded)

        if probe.action == Action.BLOCK:
            return Decision(
                allowed=False,
                action=Action.BLOCK,
                decided_by="tier2",
                output=None,
                reason=_combined_reason(tr1, probe),
                latency_ms=latency_ms,
                cost_estimate=cost,
                cost_saved=0.0,
                request_id=request_id,
                tier1_result=tr1,
                tier2_result=probe,
            )

        redacted = probe.action == Action.REDACT and probe.output is not None
        return Decision(
            allowed=True,
            action=max(tr1.action, probe.action),
            decided_by="tier2",
            output=probe.output if redacted else forwarded,
            reason=_combined_reason(tr1, probe),
            latency_ms=latency_ms,
            cost_estimate=cost,
            cost_saved=0.0,
            request_id=request_id,
            tier1_result=tr1,
            tier2_result=probe,
        )

    def _record(self, text: str, decision: Decision) -> None:
        tr1 = decision.tier1_result
        probe = decision.tier2_result
        fired = [r.guardrail for r in tr1.results if r.action != Action.ALLOW]
        detail: dict = {r.guardrail: r.detail for r in tr1.results if r.action != Action.ALLOW and r.detail}

        # Tier two only counts as a guardrail that fired when it was the decider.
        # On a short-circuit the probe is an audit measurement, recorded under
        # "shadow" so it is never mistaken for the deciding check.
        shadow: dict | None = None
        if decision.decided_by == "tier2" and probe is not None and probe.action != Action.ALLOW:
            fired.append(probe.guardrail)
            if probe.detail:
                detail[probe.guardrail] = probe.detail
        elif decision.decided_by == "tier1" and probe is not None:
            shadow = {"provider": probe.guardrail, "action": probe.action.name, "detail": probe.detail}

        self.ledger.append(
            {
                "request_id": decision.request_id,
                "decided_by": decision.decided_by,
                "action": decision.action.name,
                "allowed": decision.allowed,
                "guardrails_fired": fired,
                "reason": decision.reason,
                "token_estimate": self.cost_model.tokens(text),
                "latency_ms": decision.latency_ms,
                "cost_estimate": decision.cost_estimate,
                "cost_saved": decision.cost_saved,
                "shadow_agreement": decision.shadow_agreement,
                "shadow": shadow,
                "detail": detail,
            }
        )
