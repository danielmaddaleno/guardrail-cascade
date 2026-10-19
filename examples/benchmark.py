"""Measure the cascade against a real tier two: cost, latency and where it errs.

    $ pip install -e ".[claude]"
    $ export ANTHROPIC_API_KEY=...
    $ python examples/benchmark.py                      # Claude Haiku as tier two
    $ python examples/benchmark.py --model claude-sonnet-5-5

The same hand-labeled prompts (examples/bench_prompts.jsonl) run twice: through
the cascade, where tier two only sees what tier one escalates, and through the
model alone on every prompt. Cost comes from the token counts the API returns,
not from the character estimate the ledger uses. This calls the paid API: one
run of the bundled 58 prompts on Haiku costs well under one cent.

The set is small and labeled by hand, so read the numbers as a comparison
between the two setups on the same traffic, not as a precision eval.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import time
from collections import Counter

from guardrail_cascade import (
    CascadePolicy,
    CheckResult,
    ClaudeProvider,
    EvidenceLedger,
    PIIGuard,
    PromptInjectionGuard,
    SecretGuard,
    Tier,
    Tier2Provider,
    ToxicityGuard,
)

# USD per million tokens (input, output), list prices for prompts under 100K tokens.
PRICES = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-opus-5-5": (4.00, 20.00),
}

PROMPTS_PATH = os.path.join(os.path.dirname(__file__), "bench_prompts.jsonl")


class MeteredProvider(Tier2Provider):
    """Wraps a provider and keeps the real token counts and latency of every call."""

    def __init__(self, inner: ClaudeProvider):
        self.inner = inner
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.latencies_ms: list[float] = []

    @property
    def name(self) -> str:
        return self.inner.name

    def check(self, text: str) -> CheckResult:
        start = time.monotonic()
        result = self.inner.check(text)
        self.latencies_ms.append((time.monotonic() - start) * 1000.0)
        self.calls += 1
        self.input_tokens += result.detail.get("input_tokens", 0)
        self.output_tokens += result.detail.get("output_tokens", 0)
        return result

    def cost(self, model: str) -> float:
        price_in, price_out = PRICES[model]
        return (self.input_tokens * price_in + self.output_tokens * price_out) / 1e6


def load_prompts(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def p95(values: list[float]) -> float:
    if len(values) < 2:
        return values[0] if values else 0.0
    return statistics.quantiles(values, n=20)[-1]


def score(rows: list[dict], verdicts: list[str]) -> dict:
    wrong = [(row, got) for row, got in zip(rows, verdicts) if got != row["expect"]]
    return {
        "correct": len(rows) - len(wrong),
        "false_blocks": [row for row, got in wrong if got == "block"],
        "misses": [row for row, got in wrong if got == "allow"],
    }


def run_cascade(rows: list[dict], provider: MeteredProvider) -> tuple[list[str], list[float]]:
    tier1 = Tier("heuristics", [SecretGuard(), PromptInjectionGuard(), PIIGuard(), ToxicityGuard()])
    policy = CascadePolicy(tier1, provider, EvidenceLedger())
    verdicts, latencies = [], []
    for row in rows:
        decision = policy.evaluate(row["text"])
        verdicts.append("allow" if decision.allowed else "block")
        latencies.append(decision.latency_ms)
    return verdicts, latencies


def run_model_only(rows: list[dict], provider: MeteredProvider) -> list[str]:
    return ["block" if provider.check(row["text"]).action.name == "BLOCK" else "allow" for row in rows]


def report(label: str, rows: list[dict], verdicts: list[str], provider: MeteredProvider, latencies, model: str):
    result = score(rows, verdicts)
    print("\n== %s ==" % label)
    print("accuracy        %d/%d" % (result["correct"], len(rows)))
    print("tier-two calls  %d of %d prompts" % (provider.calls, len(rows)))
    print("tokens          %d in / %d out" % (provider.input_tokens, provider.output_tokens))
    print(
        "cost            $%.6f  ($%.2f per million requests)"
        % (provider.cost(model), provider.cost(model) / len(rows) * 1e6)
    )
    print("latency         p50 %.0f ms, p95 %.0f ms" % (statistics.median(latencies), p95(latencies)))
    for kind, rows_ in (("false blocks", result["false_blocks"]), ("misses", result["misses"])):
        by_kind = Counter(row["kind"] for row in rows_)
        print("%-15s %d %s" % (kind, len(rows_), dict(by_kind) if by_kind else ""))
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", default="claude-haiku-5-5", choices=sorted(PRICES))
    parser.add_argument("--prompts", default=PROMPTS_PATH)
    parser.add_argument("--show-misses", action="store_true", help="print the text of every wrong verdict")
    args = parser.parse_args()

    rows = load_prompts(args.prompts)
    print("%d prompts, tier two = %s" % (len(rows), args.model))

    cascade_provider = MeteredProvider(ClaudeProvider(model=args.model))
    verdicts, latencies = run_cascade(rows, cascade_provider)
    cascade = report("cascade (heuristics, then the model)", rows, verdicts, cascade_provider, latencies, args.model)

    alone_provider = MeteredProvider(ClaudeProvider(model=args.model))
    verdicts = run_model_only(rows, alone_provider)
    alone = report(
        "model alone on every prompt", rows, verdicts, alone_provider, alone_provider.latencies_ms, args.model
    )

    if args.show_misses:
        for label, result in (("cascade", cascade), ("model alone", alone)):
            for row in result["false_blocks"] + result["misses"]:
                print("[%s] expected %s: %s" % (label, row["expect"], row["text"]))


if __name__ == "__main__":
    main()
