![Tests](https://github.com/danielmaddaleno/guardrail-cascade/actions/workflows/tests.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

# guardrail-cascade

A two-tier guardrail cascade for LLM serving. Cheap heuristics dispose of the
requests they are confident about; only the ambiguous ones go to a paid,
model-based provider; and every decision is written to a hash-chained ledger
that also tracks latency and cost.

## Why

Screening every LLM call with a strong model-based guardrail is accurate but
slow and expensive. Screening with heuristics alone is fast and free but misses
things. This composes the two: tier one decides the confident cases (a clear
allow or a clear block) on its own, and tier two is paid only for the ambiguous
middle. The money saved by short-circuiting the confident traffic is a number
you can read off the ledger.

```
request -> [ tier 1: heuristics ]
              |  ALLOW or BLOCK  -> decide here (free); record; optionally
              |                     shadow-sample to tier 2 to audit the call
              |  FLAG or REDACT  -> escalate (the ambiguous middle)
              v
        [ tier 2: paid provider ] -> ALLOW / BLOCK / REDACT  (final)
              v
        [ evidence ledger ]  append-only, hash-chained,
                             latency + tokens + cost per request
```

## Quick start

```python
from guardrail_cascade import (
    CascadePolicy, Tier, EvidenceLedger, StubProvider,
    SecretGuard, PromptInjectionGuard, PIIGuard, ToxicityGuard,
)

ledger = EvidenceLedger()
tier1 = Tier("heuristics", [SecretGuard(), PromptInjectionGuard(), PIIGuard(), ToxicityGuard()])
tier2 = StubProvider(block_keywords=["malware", "weapon"])   # swap for Bedrock or Llama Guard
policy = CascadePolicy(tier1, tier2, ledger)

clean = policy.evaluate("What is the capital of France?")
clean.decided_by       # "tier1"  (a confident allow, tier 2 never called)
clean.cost_saved       # the tier-two spend this short-circuit avoided

blocked = policy.evaluate("here is my key AKIAIOSFODNN7EXAMPLE")
blocked.decided_by     # "tier1"  (a confident block, also free)

pii = policy.evaluate("Summarize the account for john.doe@acme.com")
pii.decided_by         # "tier2"  (REDACT is ambiguous, so it escalates)
pii.output             # "Summarize the account for [EMAIL]"  (masked by tier 1 first)

print(ledger.summary())  # block rates per tier, cost saved, latency percentiles
assert ledger.verify()   # the audit chain is intact
```

Run the full offline demo:

```bash
python examples/demo.py
```

## What each tier does

Tier one runs cheap, precompiled heuristics and returns one of four actions:

- `BLOCK` on high-precision signals only (structured secrets, the clearest
  injection phrases). A block is high-precision by design, so tier one takes it
  on its own.
- `ALLOW` when nothing fires, including the fuzzy checks. Also decided on its
  own.
- `REDACT` PII in place and escalate the masked text.
- `FLAG` fuzzy signals (toxicity keywords) without blocking, and escalate.

`ALLOW` and `BLOCK` short-circuit; `FLAG` and `REDACT` are the ambiguous middle
that escalates to tier two. Tier two is any model-based guardrail behind a
one-method interface (`Tier2Provider`). The bundled `StubProvider` is
deterministic and offline, so the whole pipeline runs in CI with no credentials.
Adapters for AWS Bedrock Guardrails and Llama Guard are on the roadmap.

The tradeoff of short-circuiting a confident allow is that a tier-one false
negative passes without a second opinion. Shadow sampling is the answer: tier
one sends a configurable fraction of its short-circuits to tier two anyway (off
the hot path in production) and records whether tier two agreed, which surfaces
both false positives on blocks and false negatives on allows. A block flagged
sensitive (a matched secret) is never shadowed, so the credential is not
forwarded to the paid tier even for audit.

## Cost and audit in one place

The evidence ledger appends one hash-chained entry per request. Each entry
records the action, which tier decided, which guardrail fired and its structured
detail, a token estimate, latency, and the cost incurred or saved. That makes it
both the audit trail a governance review asks for and the observability and
FinOps surface an engineer wants. `summary()` reports the short-circuit rate and
the tier-two spend it avoided.

The improvement loop closes it: `CandidateMiner` groups the misses (requests
tier two blocked after escalation, plus tier-one allows a shadow probe
disagreed with) into ranked proposals for a human to review, rather than editing
rules automatically. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for why a
human stays in the loop and how shadow sampling counters the selection bias in
that signal.

## Project structure

```
guardrail_cascade/
  core.py         # Action, CheckResult, the Guardrail interface
  heuristics.py   # tier-one guardrails: secrets, injection, PII, toxicity
  providers.py    # Tier2Provider interface + offline StubProvider
  cascade.py      # Tier combination + CascadePolicy orchestrator
  ledger.py       # EvidenceLedger, CostModel, LedgerSummary
  feedback.py     # CandidateMiner, RuleProposal (human in the loop)
tests/            # unit tests for every module
examples/demo.py  # end-to-end offline run
docs/             # ARCHITECTURE.md, ROADMAP.md
```

## Install

```bash
git clone https://github.com/danielmaddaleno/guardrail-cascade.git
cd guardrail-cascade
pip install -e ".[dev]"
```

## Development

```bash
make test     # pytest
make lint      # black --check + flake8 + mypy
make demo      # run the offline example
```

## Limitations

The tier-one guardrails are regex heuristics, not trained classifiers. They are
a cheap, high-precision first pass, not the last line of defense, and there is
no labeled precision eval in the repo yet, so "high-precision" is a design goal,
not a measured number.

The ledger hash chain detects accidental or partial edits to the log: change one
past field and `verify()` fails. It is not a defense against an attacker with
full read and write access, who could rewrite an entry and recompute every later
hash forward, because the chain has no external anchor (a published head hash or
a signature). Adding one is on the roadmap.

The bundled tier two is an offline stub for demos and tests; a real deployment
plugs in a model-based provider. Token cost is estimated from character length,
which is close enough for accounting but is not an exact tokenizer count.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md). Highlights: provider adapters (Bedrock,
Llama Guard), async off-path shadow sampling, a signed or published ledger head
hash, a ledger report renderer, a typed policy schema, and a learned tier 1.5
trained on tier-two labels plus shadow-sampled allows.

## License

MIT, see [LICENSE](LICENSE).
