"""Command-line interface: run the cascade over stdin, report over a ledger file.

Two subcommands, both offline and credential-free so they run anywhere:

    $ echo "here is my key AKIAIOSFODNN7EXAMPLE" | guardrail-cascade check
    BLOCK by tier1   a hardcoded secret or credential was detected

    $ guardrail-cascade check --ledger run.jsonl < prompts.txt
    $ guardrail-cascade report run.jsonl

``check`` reads one prompt per line from stdin (or the whole input as a single
prompt with ``--single``), runs the four bundled heuristics as tier one against
an offline stub tier two, prints one decision per prompt, and can persist the
evidence ledger to a JSON Lines file. ``report`` loads such a file, verifies the
hash chain, and prints the aggregate summary.

The default tier two is the offline stub, so nothing reaches the network; a real
deployment wires a model-based provider in code (see docs/ROADMAP.md). ``check``
exits 1 if any prompt was blocked, so it composes in a shell pipeline, and
``report`` exits 1 if the loaded ledger chain does not verify.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence, TextIO

from guardrail_cascade.cascade import CascadePolicy, Tier
from guardrail_cascade.heuristics import PIIGuard, PromptInjectionGuard, SecretGuard, ToxicityGuard
from guardrail_cascade.ledger import EvidenceLedger
from guardrail_cascade.providers import StubProvider


def build_default_tier1() -> Tier:
    """The four bundled heuristics, in escalating severity order."""
    return Tier("heuristics", [SecretGuard(), PromptInjectionGuard(), PIIGuard(), ToxicityGuard()])


def read_prompts(stream: TextIO, single: bool) -> list[str]:
    """Read prompts from *stream*: one per non-blank line, or all of it if *single*."""
    text = stream.read()
    if single:
        stripped = text.strip()
        return [stripped] if stripped else []
    return [line.strip() for line in text.splitlines() if line.strip()]


def _cmd_check(args: argparse.Namespace, stdin: TextIO, stdout: TextIO) -> int:
    prompts = read_prompts(stdin, args.single)
    tier2 = StubProvider(block_keywords=args.block_keyword or [])
    ledger = EvidenceLedger(path=args.ledger)
    policy = CascadePolicy(build_default_tier1(), tier2, ledger)

    blocked_any = False
    for prompt in prompts:
        decision = policy.evaluate(prompt)
        if not decision.allowed:
            blocked_any = True
        if args.json:
            # The stored ledger entry is already PII-scrubbed and JSON-safe, so
            # emitting it verbatim never leaks a raw secret the prompt carried.
            stdout.write(json.dumps(ledger.entries[-1], ensure_ascii=False) + "\n")
        else:
            verdict = "ALLOW" if decision.allowed else "BLOCK"
            reason = decision.reason or "(no signal fired)"
            stdout.write("%-5s by %-6s  %s\n" % (verdict, decision.decided_by, reason))
    return 1 if blocked_any else 0


def _cmd_report(args: argparse.Namespace, stdin: TextIO, stdout: TextIO) -> int:
    ledger = EvidenceLedger.load(args.ledger_file)
    ok = ledger.verify()
    summary = ledger.summary()
    lines = [
        "Ledger file:         %s" % args.ledger_file,
        "Chain valid:         %s" % ok,
        "Requests:            %d" % summary.total,
        "Allowed:             %d" % summary.allowed,
        "Blocked by tier 1:   %d" % summary.blocked_by_tier1,
        "Blocked by tier 2:   %d" % summary.blocked_by_tier2,
        "Short-circuit rate:  %.0f%%" % (summary.short_circuit_rate * 100),
        "Tier-two cost spent: $%.6f" % summary.cost_incurred,
        "Tier-two cost saved: $%.6f" % summary.cost_saved,
        "Latency p50 / p95:   %.2f ms / %.2f ms" % (summary.latency_p50_ms, summary.latency_p95_ms),
    ]
    stdout.write("\n".join(lines) + "\n")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail-cascade",
        description="Run the two-tier guardrail cascade and report over its evidence ledger.",
    )
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="screen prompts read from stdin")
    check.add_argument("--single", action="store_true", help="treat all of stdin as one prompt, not one per line")
    check.add_argument("--json", action="store_true", help="emit the scrubbed ledger entry as JSON per prompt")
    check.add_argument("--ledger", metavar="PATH", help="append the evidence ledger to this JSON Lines file")
    check.add_argument(
        "--block-keyword",
        action="append",
        metavar="WORD",
        help="a tier-two block keyword for the offline stub provider (repeatable)",
    )
    check.set_defaults(func=_cmd_check)

    report = sub.add_parser("report", help="summarize a ledger JSON Lines file")
    report.add_argument("ledger_file", help="path to a JSON Lines ledger written by `check --ledger`")
    report.set_defaults(func=_cmd_report)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help(sys.stderr)
        return 2
    return int(args.func(args, sys.stdin, sys.stdout))


if __name__ == "__main__":
    sys.exit(main())
