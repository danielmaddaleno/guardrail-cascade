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
tier2 = StubProvider(block_keywords=["malware", "weapon"])   # or ClaudeProvider() for a real model
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

Installing the package puts a `guardrail-cascade` command on your path. By
default it runs the same offline cascade, so it needs no credentials.

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
`--claude` uses a Claude model as tier two instead (`--model` picks which one),
which calls the paid API.

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
- `REDACT` PII in place and escalate the masked text. The digit rules need a
  separator, a labeling word or a passing Luhn checksum, because an order id
  masked by mistake escalates a request that tier one could have settled.
- `FLAG` fuzzy signals (toxicity keywords) without blocking, and escalate.

`ALLOW` and `BLOCK` short-circuit; `FLAG` and `REDACT` are the ambiguous middle
that escalates to tier two. Tier two is any model-based guardrail behind a
one-method interface (`Tier2Provider`). The bundled `StubProvider` is
deterministic and offline, so the whole pipeline runs in CI with no credentials.
`ClaudeProvider` is the real one: it asks a Claude model (Haiku by default) for
an allow or block verdict and a category, constrained to a JSON schema.

```python
from guardrail_cascade import ClaudeProvider   # pip install "guardrail-cascade[claude]"

tier2 = ClaudeProvider()                  # reads ANTHROPIC_API_KEY
tier2 = ClaudeProvider(fail_open=True)    # let traffic through as FLAG if the API is down
```

The request goes in as data inside tags, never as instructions. The ledger
reason is built from the category, so the model's prose never reaches the log. A
model refusal counts as a block, and an API error or an unusable answer fails
closed unless `fail_open` is set. On Haiku a check costs about 600 input tokens
and adds one to two seconds to an escalated request.
Adapters for AWS Bedrock Guardrails and Llama Guard are still on the roadmap.

The tradeoff of short-circuiting a confident allow is that a tier-one false
negative passes without a second opinion. Shadow sampling is the answer: tier
one sends a configurable fraction of its short-circuits to tier two anyway (off
the hot path in production) and records whether tier two agreed, which surfaces
both false positives on blocks and false negatives on allows. A block flagged
sensitive (a matched secret) is never shadowed, so the credential is not
forwarded to the paid tier even for audit. A probe that does go out carries the
text tier one already redacted, so a masked value is not un-masked on the way.

## Measured against a real tier two

`examples/benchmark.py` sends 58 hand-labeled prompts through the cascade and
then through the model alone: benign requests, PII, benign text that trips the
toxicity keywords, harmful requests, prompt injections and pasted credentials.
Tier two is Claude Haiku 5.5 and the cost comes from the token counts the API
returns.

| | Cascade | Model alone |
|---|---|---|
| Correct | 42 / 58 | 55 / 58 |
| Wrongly blocked | 0 | 0 |
| Missed | 16 | 3 |
| Tier-two calls | 18 | 58 |
| Cost per million requests | $21 | $71 |
| Latency p50 / p95 | 0 / 1326 ms | 1237 / 1823 ms |

The cascade is about 70% cheaper and misses five times as many. Every one of its
16 misses is a request where no heuristic fired: rephrased injections ("you are
now DAN") and harmful asks with no keyword in them (a keylogger, ransomware, a
pipe bomb). Tier one returns a confident ALLOW, the request short-circuits, and
the model never sees it. The model alone missed only the three pasted
credentials, which tier one blocks on its own. The two error sets do not
overlap, so a short-circuited allow is only as good as the regexes behind it.
Shadow sampling measures that gap but does not close it. On this traffic the
safer setup lets tier one decide blocks only and sends every allow to tier two,
which the roadmap adds as a policy option.

The set is small and labeled by hand, so treat it as a comparison of the two
setups on the same traffic, not as a precision eval. Two runs gave the same
verdicts and cost; latency moved by about 10%. Run it yourself with
`pip install -e ".[claude]"` and `python examples/benchmark.py` (well under one
cent on Haiku).

## Cost and audit in one place

The evidence ledger appends one hash-chained entry per request. Each entry
records the action, which tier decided, which guardrail fired and its structured
detail, a token estimate, latency, and the cost incurred or saved. Every entry is
scrubbed before it is stored, so a raw value a custom guardrail or provider left
in a field is masked when it matches a shape the scrubber knows: emails, phone
numbers, SSNs, card numbers, and the credential formats with a fixed prefix (AWS,
GitHub, Google, OpenAI, Stripe live keys, JWTs, PEM private key headers). The
list is finite and worth reading before trusting it: a credential shape that is
not on it, and PII with no shape at all such as a person's name, still reach the
log. That makes it both the audit trail a governance review asks for and the
observability and FinOps surface an engineer wants. `summary()` reports the short-circuit rate
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
  providers.py    # Tier2Provider interface, ClaudeProvider, offline StubProvider
  cascade.py      # Tier combination + CascadePolicy orchestrator
  ledger.py       # EvidenceLedger, CostModel, LedgerSummary
  scrub.py        # PII/secret masking applied to every ledger entry
  feedback.py     # CandidateMiner, RuleProposal (human in the loop)
  policy.py       # PolicySpec: the deployed configuration as a reviewable file
  governance.py   # control catalog, framework crosswalk, lint gate, system card
  cli.py          # `check` / `report` / `lint` / `card` command line
tests/            # unit tests for every module
examples/demo.py  # end-to-end offline run
examples/benchmark.py  # cascade vs model alone on labeled prompts (paid API)
examples/bench_prompts.jsonl  # the 58 labeled prompts it runs
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

The default tier two is an offline stub for demos and tests. `ClaudeProvider`
is the model-based one, and there is no labeled eval of its verdicts in the repo
yet either. Token cost is estimated from character length,
which is close enough for accounting but is not an exact tokenizer count.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md). Highlights: more provider adapters
(Bedrock, Llama Guard), async off-path shadow sampling, a signed or published ledger head
hash, a ledger report renderer, and a learned tier 1.5 trained on tier-two
labels plus shadow-sampled allows.

## License

MIT, see [LICENSE](LICENSE).
