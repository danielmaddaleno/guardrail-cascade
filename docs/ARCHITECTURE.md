# Architecture

## The problem

Every call to an LLM crosses two trust boundaries: the prompt going in and the
response coming back. Screening both with a strong model-based guardrail on
every request is accurate but slow and expensive. Screening with cheap
heuristics alone is fast and free but misses a lot. This project composes the
two into a cascade so the confident traffic is decided cheaply and the expensive
tier is reserved for the requests that actually need it.

## The cascade

```
request
   |
   v
[ tier 1: heuristics ]   cheap, near-zero latency, deterministic
   |   BLOCK  -> decide here (free); record; optionally shadow-sample to audit
   |   ALLOW  -> decide here (free); record; optionally shadow-sample to audit
   |   REDACT -> mask in place and escalate the masked text
   |   FLAG   -> escalate
   v
[ tier 2: model-based provider ]   paid; reached only for FLAG / REDACT (and
   |                               for shadow-sampled short-circuits)
   |   BLOCK / ALLOW / REDACT -> final
   v
[ evidence ledger ]   append-only, hash-chained; records action, which tier
                      decided, the guardrail that fired and its detail, latency,
                      token estimate, and cost incurred/saved
```

The routing rule is confidence-based: `ALLOW` and `BLOCK` are the confident
verdicts and short-circuit; `FLAG` and `REDACT` are the ambiguous middle and
escalate. Savings come from short-circuiting the confident traffic, which in
typical input is most of it.

## Three decisions that make it defensible

These are the parts an interviewer will poke at. Each is a deliberate choice,
not an accident.

### 1. Tier one only hard-blocks high-precision signals

A cheap filter that blocks on fuzzy signals will produce false positives, and a
false positive silently hurts a real user. So tier one blocks only where a match
is high-precision (structured secrets, the clearest injection phrases), redacts
where masking is safe (PII), and otherwise `FLAG`s. A `FLAG` never blocks on its
own; it escalates to tier two. That keeps a noisy keyword rule from quietly
degrading the product. "High-precision" here is a design goal, not a measured
number: there is no labeled eval set in the repo yet (see the roadmap).

### 2. Shadow sampling measures what a short-circuit hides

By construction, a request decided at tier one never reaches tier two, so tier
one's own error rate is invisible: its false positives on blocks and its false
negatives on allows. `CascadePolicy` can send a configurable fraction of both
kinds of short-circuit to tier two anyway (off the hot path in production) and
record whether tier two agreed. A shadow probe is a real, billed tier-two call
and it never changes the decision, only measures it, so the ledger books it as
cost incurred, not cost saved. One exception: a block whose result is marked
sensitive (a matched secret) is never shadowed, because forwarding the credential
to the paid tier would defeat the block. Without this sampling, tier one could
drift and nobody would notice.

### 3. The improvement loop keeps a human in the middle

Two things say tier one should improve: a request tier two blocked after
escalation, and a tier-one allow whose shadow probe disagreed. Both are mined
into ranked proposals for a person to review. The tempting shortcut is to
synthesize a regex from the example by machine, which overfits and can introduce
catastrophic backtracking, so a human stays in the loop. A learned tier could
also be trained on these labels, with one caveat below.

#### Selection bias in the training signal

Escalated catches only describe misses among traffic tier one already flagged,
not the true input distribution. The shadow-sampled allows are the one source of
labels on traffic tier one let straight through, so folding them into the miner
(decision 2 feeding decision 3) is what unbiases the signal. This is why the two
mechanisms belong together.

## The evidence ledger

Each decision appends one entry. `entry_hash = sha256(prev_hash + canonical_json(fields))`,
so editing any past field or dropping a line breaks the chain and `verify()`
returns false. This detects accidental or partial edits. It is not a defense
against an attacker with full read and write access, who could rewrite an entry
and recompute every later hash forward: the chain has no external anchor (a
published head hash or a signature) yet. The `prev_hash` and `entry_hash` keys
are reserved, so a caller cannot inject them through `append`. A ledger opened
over a JSON Lines file that already exists reads it back first, so the next
append continues that chain rather than starting a second one in the same file.

The same entries carry `token_estimate`, `latency_ms`, `cost_estimate`, and
`cost_saved`, so the ledger is simultaneously the audit trail a governance review
wants and the observability and cost surface an engineer wants. `summary()` rolls
it up: block rates per tier, cost incurred versus saved, and latency percentiles.

Before an entry is hashed and stored, it is scrubbed (`guardrail_cascade.scrub`):
PII and secret-shaped substrings in every string field are masked. The built-in
guardrails only put labels in a result, never raw values, but a custom guardrail
or a real tier-two provider could return the offending span, so the ledger masks
defensively rather than trusting its callers. The scrubber is independent of the
detection heuristics on purpose: the log must be safe even when no PII guardrail
is configured.

## The governance layer

The cascade's mechanisms only count as *controls* when a reviewer can check
they are deployed and see the evidence they ran. Two modules turn the
mechanisms into exactly that:

**Policy as code (`policy`).** `PolicySpec` is the deployed configuration
(which guardrails run, the shadow rate, the price model) as one typed object
loadable from a JSON (or YAML) file. The schema is closed: an unknown key is an
error, because a typo like `shadow_smaple_rate` silently disabling sampling is
the exact failure a reviewed policy exists to prevent. `spec.build()` wires the
whole cascade from the file and refuses an invalid spec, so the reviewed
artifact and the running configuration cannot quietly diverge.

**Controls, crosswalk, and evidence (`governance`).** `CONTROL_CATALOG` names
the seven controls the cascade implements (input screening, secret
containment, PII redaction, the audit trail, log scrubbing, drift monitoring,
human oversight) and crosswalks each to NIST AI RMF functions, ISO/IEC 42001
clauses, and EU AI Act articles. The crosswalk is deliberately coarse (function
and clause level) because a wrong subcategory number is worse than a right
coarse one; it is a documentation aid, not a certification claim.
`assess_controls` judges a policy against the catalog, and a supplied ledger
both enriches the evidence (probes sent, agreement observed) and can *fail* a
structural control: a ledger whose hash chain does not verify fails
`audit-trail` even though the ledger exists.

Two consumers close the loop:

- **`lint_policy` is the CI gate.** A build fails when the policy is invalid
  or a required control is unsatisfied, the same way it fails on a broken
  test. This repo's own CI lints `examples/policy.json`. Narrowing the
  required set is possible but explicit, so accepting a gap is a reviewable
  decision, not an omission.
- **`system_card` is the generated document.** Policy plus ledger render into
  a Markdown system card: the deployed configuration, the control table with
  its crosswalk and per-control evidence, and the operational numbers
  (short-circuit rate, cost, latency, shadow agreement, chain validity). A
  generated card cannot drift from reality the way a hand-written one does,
  and it inherits the ledger's scrubbing, so no raw traffic value can leak
  into the published document.

## Module map

| Module | Responsibility |
| --- | --- |
| `core` | `Action`, `CheckResult`, the `Guardrail` interface |
| `heuristics` | Concrete tier-one guardrails (secrets, injection, PII, toxicity) |
| `providers` | `Tier2Provider` interface and the offline `StubProvider` |
| `cascade` | `Tier` combination logic and the `CascadePolicy` orchestrator |
| `ledger` | `EvidenceLedger`, `CostModel`, `LedgerSummary` |
| `scrub` | PII and secret masking applied to every ledger entry |
| `feedback` | `CandidateMiner`, `RuleProposal` (human-in-the-loop) |
| `policy` | `PolicySpec`: the deployed configuration as a validated, reviewable file |
| `governance` | Control catalog, framework crosswalk, `lint_policy` gate, `system_card` |

## Non-goals (for now)

This is a single governed serving path, not a platform. It does not try to be an
LLM gateway across many providers, an agent-orchestration framework, or a
benchmark suite. See ROADMAP.md for what is added incrementally.
