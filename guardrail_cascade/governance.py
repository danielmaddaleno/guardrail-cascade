"""Governance layer: name the controls, check they are deployed, produce the evidence.

A governance review of an LLM serving path asks three questions the code alone
does not answer: *which* risk controls exist, *whether* the deployed policy
actually has them turned on, and *what evidence* shows they ran. This module
answers all three from artifacts the repo already produces:

- :data:`CONTROL_CATALOG` names each control the cascade implements and
  crosswalks it to NIST AI RMF 1.0 functions, ISO/IEC 42001:2023 clauses, and
  EU AI Act articles, so one mechanism maps to the language each framework
  reviewer speaks.
- :func:`assess_controls` checks a :class:`~guardrail_cascade.policy.PolicySpec`
  (and optionally a ledger) against the catalog: a control is satisfied or it
  is not, with the evidence stated.
- :func:`lint_policy` is the CI gate the roadmap promised: a build fails when a
  required control is missing from the policy, the same way it fails when a
  test does.
- :func:`system_card` renders policy plus ledger into a Markdown system card,
  so the document a review asks for is generated from the deployed truth
  instead of hand-written and stale.

The crosswalk is deliberately conservative: NIST references stay at the
function level and ISO references at the clause level, because a wrong
subcategory number is worse than a coarse right one. It is a documentation aid
for a review, not a certification claim, and the card says so.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Sequence

from guardrail_cascade.ledger import EvidenceLedger
from guardrail_cascade.policy import PolicySpec


@dataclass(frozen=True)
class FrameworkRef:
    """One crosswalk reference: a framework, the place in it, and why it applies."""

    framework: str
    citation: str
    note: str


@dataclass(frozen=True)
class Control:
    """A risk control the cascade implements, with its crosswalk references.

    ``mechanism`` names the code that implements the control, so a reviewer can
    go from the claim to the implementation in one hop.
    """

    control_id: str
    title: str
    mechanism: str
    description: str
    references: tuple[FrameworkRef, ...]


@dataclass
class ControlAssessment:
    """Whether one control is satisfied by a concrete policy, and the evidence."""

    control: Control
    satisfied: bool
    evidence: str


CONTROL_CATALOG: tuple[Control, ...] = (
    Control(
        control_id="input-screening",
        title="Every request is screened before serving",
        mechanism="cascade.Tier + heuristics.*",
        description=(
            "Tier-one guardrails run on every request; confident verdicts short-circuit and the "
            "ambiguous middle escalates to the model-based tier, so no request reaches the model unchecked."
        ),
        references=(
            FrameworkRef("NIST AI RMF", "MANAGE", "risks are responded to with deployed mitigations"),
            FrameworkRef("ISO/IEC 42001", "Clause 8", "operational planning and control"),
            FrameworkRef("EU AI Act", "Art. 9", "risk management system"),
        ),
    ),
    Control(
        control_id="secret-containment",
        title="Credential-like secrets are blocked and never forwarded",
        mechanism="heuristics.SecretGuard + cascade.CascadePolicy",
        description=(
            "Structured secrets are blocked at tier one, and a block marked sensitive is excluded from "
            "shadow sampling, so the credential is not sent to the paid tier even for audit."
        ),
        references=(
            FrameworkRef("NIST AI RMF", "MEASURE", "security and resilience are evaluated"),
            FrameworkRef("ISO/IEC 42001", "Clause 8", "operational planning and control"),
            FrameworkRef("EU AI Act", "Art. 15", "accuracy, robustness and cybersecurity"),
        ),
    ),
    Control(
        control_id="pii-redaction",
        title="PII is masked before text is forwarded",
        mechanism="heuristics.PIIGuard",
        description=(
            "Detected PII is replaced with typed labels in place and only the masked text travels to " "the next tier."
        ),
        references=(
            FrameworkRef("NIST AI RMF", "MEASURE", "privacy and data risks are examined"),
            FrameworkRef("ISO/IEC 42001", "Clause 8", "operational planning and control"),
            FrameworkRef("EU AI Act", "Art. 10", "data and data governance"),
        ),
    ),
    Control(
        control_id="audit-trail",
        title="Every decision lands in a tamper-evident ledger",
        mechanism="ledger.EvidenceLedger",
        description=(
            "One hash-chained entry per request records the action, the deciding tier, the guardrail "
            "detail, latency, tokens and cost; editing or dropping an entry breaks verify(). The chain "
            "has no external anchor yet, so it detects edits, not a full rewrite (see the roadmap)."
        ),
        references=(
            FrameworkRef("NIST AI RMF", "GOVERN", "policies and documentation provide accountability"),
            FrameworkRef("ISO/IEC 42001", "Clause 9", "performance evaluation"),
            FrameworkRef("EU AI Act", "Art. 12", "record-keeping"),
        ),
    ),
    Control(
        control_id="log-scrubbing",
        title="The audit log itself is scrubbed of PII and secrets",
        mechanism="scrub.scrub via ledger.EvidenceLedger.append",
        description=(
            "Every entry is masked before it is hashed and stored, independently of which guardrails are "
            "configured, so a raw value a custom guardrail or provider leaves in a field never reaches "
            "the log."
        ),
        references=(
            FrameworkRef("NIST AI RMF", "MANAGE", "mechanisms to minimize harms from data handling"),
            FrameworkRef("ISO/IEC 42001", "Clause 8", "operational planning and control"),
            FrameworkRef("EU AI Act", "Art. 10", "data and data governance"),
        ),
    ),
    Control(
        control_id="drift-monitoring",
        title="Short-circuits are shadow-audited against the model-based tier",
        mechanism="cascade.CascadePolicy shadow sampling",
        description=(
            "A configured fraction of tier-one allows and blocks is also sent to tier two, and the "
            "agreement is recorded, so tier-one drift is measured instead of invisible."
        ),
        references=(
            FrameworkRef("NIST AI RMF", "MEASURE", "AI system performance is tracked in deployment"),
            FrameworkRef("ISO/IEC 42001", "Clause 9", "performance evaluation"),
            FrameworkRef("EU AI Act", "Art. 9", "risk management is continuous and iterative"),
        ),
    ),
    Control(
        control_id="human-oversight",
        title="Rule changes are proposed to a human, never auto-applied",
        mechanism="feedback.CandidateMiner",
        description=(
            "Tier-one misses are mined into ranked proposals for a person to review; no rule is edited "
            "by machine, which keeps overfitted or pathological patterns out of the hot path."
        ),
        references=(
            FrameworkRef("NIST AI RMF", "GOVERN", "human oversight roles and responsibilities"),
            FrameworkRef("ISO/IEC 42001", "Clause 10", "improvement"),
            FrameworkRef("EU AI Act", "Art. 14", "human oversight"),
        ),
    ),
)


def _fired_count(entries: list[dict], guardrail: str) -> int:
    return sum(1 for e in entries if guardrail in (e.get("guardrails_fired") or []))


def _check_input_screening(policy: PolicySpec, ledger: EvidenceLedger | None) -> tuple[bool, str]:
    if not policy.guardrails:
        return False, "the policy configures no tier-one guardrails, so requests reach the model unscreened"
    evidence = "%d guardrail(s) configured: %s" % (len(policy.guardrails), ", ".join(policy.guardrails))
    if ledger is not None:
        entries = ledger.entries
        hit = sum(1 for e in entries if e.get("guardrails_fired"))
        evidence += "; %d of %d recorded requests had at least one guardrail fire" % (hit, len(entries))
    return True, evidence


def _check_named_guard(guard: str, absent: str) -> Callable[[PolicySpec, EvidenceLedger | None], tuple[bool, str]]:
    def check(policy: PolicySpec, ledger: EvidenceLedger | None) -> tuple[bool, str]:
        if guard not in policy.guardrails:
            return False, absent
        evidence = "%s is in the tier-one lineup" % guard
        if ledger is not None:
            evidence += "; it fired on %d recorded request(s)" % _fired_count(ledger.entries, guard)
        return True, evidence

    return check


def _check_audit_trail(policy: PolicySpec, ledger: EvidenceLedger | None) -> tuple[bool, str]:
    # Structural: CascadePolicy cannot be constructed without a ledger, so the
    # trail exists by design. A supplied ledger is still verified, because an
    # audit trail whose chain does not verify is evidence against the control.
    if ledger is None:
        return True, "the cascade cannot run without a ledger; every evaluate() appends one chained entry"
    ok = ledger.verify()
    evidence = "%d entries, hash chain verifies: %s" % (len(ledger.entries), ok)
    return ok, evidence


def _check_log_scrubbing(policy: PolicySpec, ledger: EvidenceLedger | None) -> tuple[bool, str]:
    # Structural: the scrubber is on by default for every append and the policy
    # schema offers no way to turn it off; only code passing scrubber=None can.
    return True, "every entry is masked before hashing by default; the policy schema cannot disable it"


def _check_drift_monitoring(policy: PolicySpec, ledger: EvidenceLedger | None) -> tuple[bool, str]:
    rate = float(policy.shadow_sample_rate)
    if rate <= 0.0:
        return False, "shadow_sample_rate is 0, so tier-one drift is not being measured"
    evidence = "shadow_sample_rate is %g" % rate
    if ledger is not None:
        summary = ledger.summary()
        if summary.shadow_probes:
            evidence += "; %d probe(s) recorded, agreement %.1f%%" % (
                summary.shadow_probes,
                summary.shadow_agreement_rate * 100.0,
            )
        else:
            evidence += "; no probes recorded yet"
    return True, evidence


def _check_human_oversight(policy: PolicySpec, ledger: EvidenceLedger | None) -> tuple[bool, str]:
    # Structural: the miner only ever emits RuleProposal objects for review;
    # nothing in the package mutates a guardrail from ledger data.
    return True, "the feedback loop emits ranked proposals only; no rule is edited without a human"


_CHECKERS: dict[str, Callable[[PolicySpec, EvidenceLedger | None], tuple[bool, str]]] = {
    "input-screening": _check_input_screening,
    "secret-containment": _check_named_guard(
        "SecretGuard", "SecretGuard is not in the policy, so credentials are not blocked at tier one"
    ),
    "pii-redaction": _check_named_guard(
        "PIIGuard", "PIIGuard is not in the policy, so PII is forwarded unmasked to the next tier"
    ),
    "audit-trail": _check_audit_trail,
    "log-scrubbing": _check_log_scrubbing,
    "drift-monitoring": _check_drift_monitoring,
    "human-oversight": _check_human_oversight,
}


def assess_controls(policy: PolicySpec, ledger: EvidenceLedger | None = None) -> list[ControlAssessment]:
    """Judge every cataloged control against *policy*, in catalog order.

    A ledger enriches the evidence with observed numbers (entries recorded,
    probes sent, chain validity) and can *fail* a structural control when the
    observation contradicts it: a broken hash chain fails ``audit-trail`` even
    though the ledger exists.
    """
    assessments = []
    for control in CONTROL_CATALOG:
        satisfied, evidence = _CHECKERS[control.control_id](policy, ledger)
        assessments.append(ControlAssessment(control=control, satisfied=satisfied, evidence=evidence))
    return assessments


def lint_policy(
    policy: PolicySpec,
    required: Sequence[str] | None = None,
    ledger: EvidenceLedger | None = None,
) -> list[str]:
    """Return every reason *policy* should fail a governance gate; empty means pass.

    This is the check the roadmap called "policy lint in CI": spec-level
    problems (:meth:`PolicySpec.validate`) plus every *required* control the
    policy does not satisfy. ``required`` defaults to the whole catalog;
    narrowing it is an explicit, reviewable statement that a deployment accepts
    running without the excluded controls.
    """
    problems = list(policy.validate())
    known = {control.control_id for control in CONTROL_CATALOG}
    wanted = list(required) if required is not None else sorted(known)
    for control_id in wanted:
        if control_id not in known:
            problems.append("unknown required control %r (catalog: %s)" % (control_id, ", ".join(sorted(known))))
    if problems:
        # With an invalid spec or an unknown requirement, control assessment
        # would report noise on top of the real problem, so stop here.
        return problems
    by_id = {a.control.control_id: a for a in assess_controls(policy, ledger)}
    for control_id in wanted:
        assessment = by_id[control_id]
        if not assessment.satisfied:
            problems.append("required control %r is not satisfied: %s" % (control_id, assessment.evidence))
    return problems


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cell(value: str) -> str:
    """Make a string safe inside a Markdown table cell.

    Policy fields are author-controlled, but the card is the one artifact meant
    to be published onward, so a pipe or newline in a policy name or keyword
    must not be able to break or reshape the table it lands in.
    """
    return value.replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def system_card(
    policy: PolicySpec,
    ledger: EvidenceLedger | None = None,
    *,
    now: Callable[[], str] = _utc_now_iso,
) -> str:
    """Render *policy* (and optionally a ledger) into a Markdown system card.

    The card is generated from the deployed configuration and the recorded
    evidence, so it cannot drift from reality the way a hand-written one does.
    Without a ledger it is a design-time card: the controls section still
    assesses the policy, and the evidence section says no traffic has been
    recorded. ``now`` is injectable so tests are deterministic.
    """
    assessments = assess_controls(policy, ledger)
    satisfied = sum(1 for a in assessments if a.satisfied)

    lines = [
        "# System card: %s (policy v%s)" % (_cell(policy.name), _cell(policy.version)),
        "",
        "Generated %s by guardrail-cascade from the deployed policy%s."
        % (now(), "" if ledger is None else " and its evidence ledger"),
        "",
        "## System",
        "",
        "A two-tier guardrail cascade for LLM serving: cheap tier-one heuristics decide the",
        "confident cases, the ambiguous middle escalates to a model-based provider, and every",
        "decision is appended to a hash-chained evidence ledger that also records latency and cost.",
        "",
        "## Deployed policy",
        "",
        "| Field | Value |",
        "| --- | --- |",
        "| Tier-one guardrails | %s |" % (_cell(", ".join(policy.guardrails)) if policy.guardrails else "(none)"),
        "| Shadow sample rate | %g |" % float(policy.shadow_sample_rate),
        "| Tier-two stub block keywords | %s |"
        % (_cell(", ".join(policy.block_keywords)) if policy.block_keywords else "(none)"),
        "| Price per 1k tokens | $%g |" % policy.price_per_1k_tokens,
        "| Chars per token | %g |" % policy.chars_per_token,
        "",
        "## Controls (%d of %d satisfied)" % (satisfied, len(assessments)),
        "",
        "| Control | Status | NIST AI RMF | ISO/IEC 42001 | EU AI Act | Evidence |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for assessment in assessments:
        control = assessment.control
        refs = {ref.framework: "%s (%s)" % (ref.citation, ref.note) for ref in control.references}
        lines.append(
            "| %s: %s | %s | %s | %s | %s | %s |"
            % (
                control.control_id,
                control.title,
                "satisfied" if assessment.satisfied else "**NOT SATISFIED**",
                refs.get("NIST AI RMF", "n/a"),
                refs.get("ISO/IEC 42001", "n/a"),
                refs.get("EU AI Act", "n/a"),
                # Evidence strings can embed policy-supplied guardrail names.
                _cell(assessment.evidence),
            )
        )

    lines += ["", "## Operational evidence", ""]
    if ledger is None:
        lines.append("No evidence ledger was provided; this is a design-time card for the policy alone.")
    else:
        summary = ledger.summary()
        agreement = (
            "%.1f%% over %d probe(s)" % (summary.shadow_agreement_rate * 100.0, summary.shadow_probes)
            if summary.shadow_probes
            else "no probes recorded"
        )
        lines += [
            "| Metric | Value |",
            "| --- | --- |",
            "| Requests recorded | %d |" % summary.total,
            "| Allowed | %d |" % summary.allowed,
            "| Blocked by tier 1 / tier 2 | %d / %d |" % (summary.blocked_by_tier1, summary.blocked_by_tier2),
            "| Short-circuit rate | %.1f%% |" % (summary.short_circuit_rate * 100.0),
            "| Tier-two cost incurred / saved | $%.6f / $%.6f |" % (summary.cost_incurred, summary.cost_saved),
            "| Latency p50 / p95 | %.2f ms / %.2f ms |" % (summary.latency_p50_ms, summary.latency_p95_ms),
            "| Shadow agreement | %s |" % agreement,
            "| Ledger chain verifies | %s |" % ledger.verify(),
        ]

    lines += [
        "",
        "## Limitations",
        "",
        "Tier-one guardrails are regex heuristics, not trained classifiers, and no labeled",
        "precision eval ships in the repo yet. The ledger chain detects edits but has no external",
        "anchor, so it does not resist an attacker who can rewrite the whole file. The framework",
        "crosswalk above is a documentation aid mapping mechanisms to the language of each",
        "framework; it is not a certification, an audit result, or legal advice.",
        "",
    ]
    return "\n".join(lines)
