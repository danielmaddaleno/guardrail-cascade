"""The cascade: let the cheap tier dispose of the confident cases, pay only for the rest.

Flow for one request:

1. Run tier one (the heuristics).
2. If tier one is confident (ALLOW or BLOCK), decide right there and skip the
   paid tier. Optionally shadow-sample a fraction of these short-circuits to
   tier two so we can measure the errors they hide: false positives on a block
   and false negatives on an allow. A shadow probe is a real tier-two call, so
   it is billed and it never changes the decision, only measures it. It carries
   whatever redactions tier one applied, so masking is not undone for an audit.
   With ``short_circuit_allow=False`` a confident ALLOW escalates instead, so
   only a BLOCK is decided by tier one alone; every allow gets the paid second
   opinion the benchmark shows it needs.
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
from typing import Callable, Protocol

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
    # Tokens behind ``cost_estimate``: the count a tier-two call actually billed
    # when it reported one, otherwise the character-length estimate.
    token_count: int = 0


def _billed_tokens(result: CheckResult | None) -> int | None:
    """The tokens a provider reports it billed, or None if it reported none.

    ``ClaudeProvider`` puts ``input_tokens`` and ``output_tokens`` from the API
    response in ``detail``; the offline stub and other providers may report
    neither, in which case the caller falls back to the character estimate.
    """
    if result is None:
        return None
    detail = result.detail
    if "input_tokens" not in detail and "output_tokens" not in detail:
        return None
    return int(detail.get("input_tokens", 0)) + int(detail.get("output_tokens", 0))


def _combined_reason(tier1: TierResult, probe: CheckResult | None) -> str:
    parts = [r.reason for r in tier1.results if r.action != Action.ALLOW and r.reason]
    if probe is not None and probe.action != Action.ALLOW and probe.reason:
        parts.append(probe.reason)
    return "; ".join(parts)


class ShadowExecutor(Protocol):
    """The slice of ``concurrent.futures.Executor`` the cascade needs.

    Only ``submit`` is used, so a real ``ThreadPoolExecutor`` satisfies this and
    a test can pass a trivial stand-in that runs the probe when it chooses.
    """

    def submit(self, fn: Callable[..., object], *args: object) -> object: ...


class CascadePolicy:
    """Orchestrates tier one, tier two, and the evidence ledger.

    ``sampler`` and ``clock`` are injected so tests are deterministic:
    ``sampler`` returns a float in ``[0, 1)`` and drives shadow sampling, and
    ``clock`` returns seconds for latency measurement.

    By default a shadow probe runs inline on the request thread (it is excluded
    from the reported latency, but it still delays the ledger write and holds the
    caller until the paid round trip returns). Pass a ``shadow_executor`` to move
    the probe and its ledger write off the request thread entirely: the decision
    is returned before the probe runs, and the audited entry is appended from the
    executor once it completes. The ledger already serializes appends across
    threads, so a background probe writes a chain that still verifies. Drain the
    executor (for example ``executor.shutdown(wait=True)``) before reading the
    ledger to be sure every probe has landed.
    """

    def __init__(
        self,
        tier1: Tier,
        tier2: Tier2Provider,
        ledger: EvidenceLedger,
        *,
        cost_model: CostModel | None = None,
        shadow_sample_rate: float = 0.0,
        short_circuit_allow: bool = True,
        sampler: Callable[[], float] = random.random,
        clock: Callable[[], float] = time.monotonic,
        shadow_executor: ShadowExecutor | None = None,
    ):
        self.tier1 = tier1
        self.tier2 = tier2
        self.ledger = ledger
        self.cost_model = cost_model or CostModel()
        self.shadow_sample_rate = shadow_sample_rate
        # When false, a tier-one ALLOW is sent to tier two instead of deciding
        # on its own; only a BLOCK short-circuits. A tier-one false negative is
        # a confident ALLOW the model never sees, so this trades the saved spend
        # for a second opinion on every allow. Shadow sampling measures that gap
        # but only closes it for the sampled fraction; this closes it for all.
        self.short_circuit_allow = short_circuit_allow
        self._sampler = sampler
        self._clock = clock
        # When set, shadow probes run here instead of inline (see class docstring).
        self._shadow_executor = shadow_executor

    def _should_shadow(self) -> bool:
        if self.shadow_sample_rate <= 0.0:
            return False
        return self._sampler() < self.shadow_sample_rate

    def evaluate(self, text: str, *, request_id: str | None = None) -> Decision:
        request_id = request_id or uuid.uuid4().hex
        start = self._clock()
        tr1 = self.tier1.run(text)

        short_circuit = tr1.action == Action.BLOCK or (tr1.action == Action.ALLOW and self.short_circuit_allow)
        if short_circuit:
            decision, deferred = self._short_circuit(text, tr1, request_id, start)
        else:
            decision, deferred = self._escalate(text, tr1, request_id, start), False

        # A deferred short-circuit hands recording to the executor thread, which
        # appends the audited entry once the background probe lands.
        if not deferred:
            self._record(decision)
        return decision

    def _short_circuit(self, text: str, tr1: TierResult, request_id: str, start: float) -> tuple[Decision, bool]:
        """Decide with tier one alone, optionally shadow-probing tier two to audit it.

        Returns the decision and whether its recording was deferred. When a probe
        is warranted and a ``shadow_executor`` was given, the probe and its ledger
        write run on that executor, off the request thread; the returned decision
        is then the pre-probe view, and ``shadow_agreement`` is filled in on the
        recorded entry rather than on the value handed back. Without an executor
        the probe runs inline, as before.
        """
        # Tier one already fixed the verdict, so stop the latency clock here,
        # before any shadow probe. The probe is a billed audit call that does not
        # change the decision; folding its round-trip into the reported latency
        # would make the p50/p95 jump whenever sampling is on.
        latency_ms = (self._clock() - start) * 1000.0
        # Never forward a sensitive block (a matched secret) to the paid tier,
        # even for audit: the whole point of the block is to stop it propagating.
        sensitive = any(r.sensitive for r in tr1.results)
        if not (self._should_shadow() and not sensitive):
            return self._short_circuit_decision(text, tr1, request_id, latency_ms, shadowed=False, probe=None), False
        if self._shadow_executor is not None:
            self._shadow_executor.submit(self._run_shadow_probe, text, tr1, request_id, latency_ms)
            return self._short_circuit_decision(text, tr1, request_id, latency_ms, shadowed=True, probe=None), True
        probe = self._shadow_probe(text, tr1)
        return self._short_circuit_decision(text, tr1, request_id, latency_ms, shadowed=True, probe=probe), False

    def _shadow_probe(self, text: str, tr1: TierResult) -> CheckResult:
        """Run the audit probe against the redacted text.

        A block can still carry PII that a redactor already masked, so the probe
        sees ``masked`` and never undoes that masking for the paid tier.
        """
        return self.tier2.check(tr1.masked if tr1.masked is not None else text)

    def _run_shadow_probe(self, text: str, tr1: TierResult, request_id: str, latency_ms: float) -> None:
        """Probe and record the audited entry, off the request thread."""
        probe = self._shadow_probe(text, tr1)
        decision = self._short_circuit_decision(text, tr1, request_id, latency_ms, shadowed=True, probe=probe)
        self._record(decision)

    def _short_circuit_decision(
        self,
        text: str,
        tr1: TierResult,
        request_id: str,
        latency_ms: float,
        *,
        shadowed: bool,
        probe: CheckResult | None,
    ) -> Decision:
        """Build the tier-one decision, with or without the shadow probe filled in.

        ``shadowed`` says a probe was or will be billed, so the avoided spend is
        not credited as saved; ``probe`` is the result once it has run, or None
        before it has (or when no probe was sampled). A probe that has run also
        settles ``shadow_agreement``.
        """
        allowed = tr1.action == Action.ALLOW
        shadow_agreement: bool | None = None
        if probe is not None:
            # Agreement means tier two would have reached the same call: block a
            # block, or leave an allow untouched. Any other verdict on an allow
            # (a REDACT or FLAG) counts as disagreement, a caught tier-one miss.
            if tr1.action == Action.BLOCK:
                shadow_agreement = probe.action == Action.BLOCK
            else:
                shadow_agreement = probe.action == Action.ALLOW
        # A shadow probe is a real tier-two call: when it reports the tokens it
        # billed, price those; otherwise fall back to the request's estimate.
        est_tokens = self.cost_model.tokens(text)
        billed = _billed_tokens(probe) if probe is not None else None
        tokens = billed if billed is not None else est_tokens
        cost = self.cost_model.cost_for_tokens(tokens)
        return Decision(
            allowed=allowed,
            action=tr1.action,
            decided_by="tier1",
            output=(tr1.output if allowed else None),
            reason=_combined_reason(tr1, None),
            latency_ms=latency_ms,
            # A shadow probe is a real tier-two call, so it costs money and does
            # not save any. Only an unshadowed short-circuit avoids the spend,
            # and that avoided spend can only ever be an estimate.
            cost_estimate=(cost if shadowed else 0.0),
            cost_saved=(0.0 if shadowed else cost),
            request_id=request_id,
            tier1_result=tr1,
            tier2_result=probe,
            shadow_agreement=shadow_agreement,
            token_count=tokens,
        )

    def _escalate(self, text: str, tr1: TierResult, request_id: str, start: float) -> Decision:
        """Send the flagged or redacted text to tier two and take its verdict."""
        forwarded = tr1.output if tr1.output is not None else text
        probe = self.tier2.check(forwarded)
        latency_ms = (self._clock() - start) * 1000.0
        # Tier two actually ran, so price the tokens it billed when it reported
        # them; only a provider that reports none falls back to the estimate.
        billed = _billed_tokens(probe)
        tokens = billed if billed is not None else self.cost_model.tokens(forwarded)
        cost = self.cost_model.cost_for_tokens(tokens)

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
                token_count=tokens,
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
            token_count=tokens,
        )

    def _record(self, decision: Decision) -> None:
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
                "token_estimate": decision.token_count,
                "latency_ms": decision.latency_ms,
                "cost_estimate": decision.cost_estimate,
                "cost_saved": decision.cost_saved,
                "shadow_agreement": decision.shadow_agreement,
                "shadow": shadow,
                "detail": detail,
            }
        )
