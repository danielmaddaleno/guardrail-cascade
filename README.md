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

## Command line

Installing the package puts a `guardrail-cascade` command on your path. It runs
the same offline cascade, so it needs no credentials.

```bash
# Screen prompts, one per line from stdin. Exit code is 1 if any is blocked,
# so it composes in a pipeline.
$ printf 'what were our top products?\nhere is my key AKIAIOSFODNN7EXAMPLE\n' | guardrail-cascade check
ALLOW by tier1   (no signal fired)
BLOCK by tier1   credential-like secret detected

# Persist the evidence ledger, then summarize it. --json emits the scrubbed
# ledger entry per prompt instead of a one-line verdict. Pointing --ledger at a
# file that already exists extends its chain, so the whole file still verifies.
$ guardrail-cascade check --ledger run.jsonl < prompts.txt
$ guardrail-cascade report run.jsonl
Chain valid:         True
Requests:            2
Short-circuit rate:  100%
Tier-two cost saved: $0.000081
...
```

`--single` treats all of stdin as one prompt, and `--block-keyword WORD`
(repeatable) configures the offline stub that stands in for the paid tier two.

The governance layer is on the command line too:

```bash
# Build the cascade from a reviewed policy file instead of the defaults.
$ guardrail-cascade check --policy examples/policy.json < prompts.txt

# The governance gate: exit 1 when the policy is invalid or misses a required
# control, so a CI build fails the way it fails on a broken test.
$ guardrail-cascade lint examples/policy.json
OK: policy 'default-serving' v1 satisfies all 7 required control(s)

# Render policy + ledger evidence into a Markdown system card.
$ guardrail-cascade card --policy examples/policy.json --ledger run.jsonl -o CARD.md
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
detail, a token estimate, latency, and the cost incurred or saved. Every entry is
scrubbed before it is stored, so PII and secret-shaped values never land in the
audit log even if a custom guardrail or provider leaves one in a field. That
makes it both the audit trail a governance review asks for and the observability
and FinOps surface an engineer wants. `summary()` reports the short-circuit rate
and the tier-two spend it avoided.

The improvement loop closes it: `CandidateMiner` groups the misses (requests
tier two blocked after escalation, plus tier-one allows a shadow probe
disagreed with) into ranked proposals for a human to review, rather than editing
rules automatically. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for why a
human stays in the loop and how shadow sampling counters the selection bias in
that signal.

## Governance: policy as code and the system card

The deployed configuration is itself a reviewable artifact. `PolicySpec` loads
the tier-one lineup, the shadow rate and the price model from a JSON file (or
YAML with the optional `[yaml]` extra), validates it (an unknown field is an
error, not a silent no-op) and builds the whole cascade from it, so what runs
is what was reviewed and versioned:

```python
from guardrail_cascade import PolicySpec, lint_policy, system_card, EvidenceLedger

spec = PolicySpec.from_file("examples/policy.json")
ledger = EvidenceLedger()
policy = spec.build(ledger=ledger)   # runnable as-is: offline stub tier two

assert lint_policy(spec) == []       # every cataloged control is satisfied
print(system_card(spec, ledger))     # Markdown system card, policy + evidence
```

Every mechanism in the cascade is cataloged as a named control
(`CONTROL_CATALOG`) and crosswalked to NIST AI RMF functions, ISO/IEC 42001
clauses and EU AI Act articles, so one implementation answers a review in the
language of each framework. `lint_policy` is the governance gate: it fails when
the policy is invalid or drops a required control, and this repo's own CI runs
it over `examples/policy.json`, so governance is enforced the way tests are.
`system_card` renders the policy plus the ledger's recorded evidence (rates,
costs, shadow agreement, chain validity) into a Markdown card, so the document
a review asks for is generated from the deployed truth instead of hand-written
and stale. The crosswalk is a documentation aid, not a certification claim, and
the card says so itself.

## Project structure

```
guardrail_cascade/
  core.py         # Action, CheckResult, the Guardrail interface
  heuristics.py   # tier-one guardrails: secrets, injection, PII, toxicity
  providers.py    # Tier2Provider interface + offline StubProvider
  cascade.py      # Tier combination + CascadePolicy orchestrator
  ledger.py       # EvidenceLedger, CostModel, LedgerSummary
  scrub.py        # PII/secret masking applied to every ledger entry
  feedback.py     # CandidateMiner, RuleProposal (human in the loop)
  policy.py       # PolicySpec: the deployed configuration as a reviewable file
  governance.py   # control catalog, framework crosswalk, lint gate, system card
  cli.py          # `check` / `report` / `lint` / `card` command line
tests/            # unit tests for every module
examples/demo.py  # end-to-end offline run
examples/policy.json  # the reviewed policy the CI governance gate lints
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
hash, a ledger report renderer, and a learned tier 1.5 trained on tier-two
labels plus shadow-sampled allows.

## License

MIT, see [LICENSE](LICENSE).
