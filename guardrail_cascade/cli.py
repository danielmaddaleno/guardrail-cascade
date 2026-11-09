"""Command-line interface: run, lint, and document the cascade from a shell.

Four subcommands, offline and credential-free by default so they run anywhere:

    $ echo "here is my key AKIAIOSFODNN7EXAMPLE" | guardrail-cascade check
    BLOCK by tier1   a hardcoded secret or credential was detected

    $ guardrail-cascade check --policy policy.json --ledger run.jsonl < prompts.txt
    $ guardrail-cascade report run.jsonl
    $ guardrail-cascade lint policy.json
    $ guardrail-cascade card --policy policy.json --ledger run.jsonl -o CARD.md

``check`` reads one prompt per line from stdin (or the whole input as a single
prompt with ``--single``), runs tier one against an offline stub tier two,
prints one decision per prompt, and can persist the evidence ledger to a JSON
Lines file, extending the chain of one that is already there. With ``--policy``
the cascade is built from a reviewed policy file instead of the built-in
defaults. ``report`` loads a ledger file, verifies the hash chain, and prints
the aggregate summary as a table, or as one JSON object with ``--json`` so the
numbers feed a dashboard without being scraped back out of the table. ``lint``
is the CI gate: it exits
1 when the policy is invalid or a required governance control is not satisfied,
so a build fails the way it fails on a broken test. ``card`` renders the policy
(and optionally a ledger) into a Markdown system card.

The default tier two is the offline stub, so nothing reaches the network.
``check --claude`` swaps in :class:`ClaudeProvider`, which calls the paid API and
needs ``ANTHROPIC_API_KEY`` and the ``[claude]`` extra. ``check``
exits 1 if any prompt was blocked, so it composes in a shell pipeline;
``report`` and ``card`` exit 1 if the loaded ledger chain does not verify, and 2
if the file is missing or cannot be read.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from typing import Callable, Sequence, TextIO

from guardrail_cascade.cascade import Tier
from guardrail_cascade.governance import CONTROL_CATALOG, lint_policy, system_card
from guardrail_cascade.ledger import EvidenceLedger
from guardrail_cascade.policy import PolicySpec
from guardrail_cascade.providers import ClaudeProvider, StubProvider, Tier2Provider


def build_default_tier1() -> Tier:
    """The four bundled heuristics, in escalating severity order."""
    return PolicySpec().build_tier1()


def read_prompts(stream: TextIO, single: bool) -> list[str]:
    """Read prompts from *stream*: one per non-blank line, or all of it if *single*."""
    text = stream.read()
    if single:
        stripped = text.strip()
        return [stripped] if stripped else []
    return [line.strip() for line in text.splitlines() if line.strip()]


def _load_policy(path: str | None) -> PolicySpec | None:
    """Load and validate a policy file, or the defaults when *path* is None.

    Problems go to stderr and ``None`` comes back, so callers can exit 2 (a
    configuration error, distinct from a blocked prompt's exit 1).
    """
    if path is None:
        return PolicySpec()
    try:
        spec = PolicySpec.from_file(path)
    except (OSError, ValueError) as exc:
        sys.stderr.write("policy error: %s\n" % exc)
        return None
    problems = spec.validate()
    if problems:
        for problem in problems:
            sys.stderr.write("policy problem: %s\n" % problem)
        return None
    return spec


def _cmd_check(args: argparse.Namespace, stdin: TextIO, stdout: TextIO) -> int:
    spec = _load_policy(args.policy)
    if spec is None:
        return 2
    prompts = read_prompts(stdin, args.single)
    # Like --block-keyword, this lets a quick experiment try the stricter mode
    # without editing the reviewed policy file.
    if args.block_only:
        spec.short_circuit_allow = False
    # Command-line keywords extend the policy's, so a quick experiment does not
    # require editing the reviewed file.
    keywords = list(spec.block_keywords) + (args.block_keyword or [])
    tier2: Tier2Provider
    if args.claude:
        try:
            tier2 = ClaudeProvider(model=args.model, fail_open=args.fail_open)
        except ImportError as exc:
            sys.stderr.write("%s\n" % exc)
            return 2
    else:
        tier2 = StubProvider(block_keywords=keywords)
    try:
        # An existing ledger file is read back so this run extends its chain.
        ledger = EvidenceLedger(path=args.ledger)
    except (OSError, ValueError) as exc:
        sys.stderr.write("ledger error: %s\n" % exc)
        return 2
    policy = spec.build(tier2=tier2, ledger=ledger)

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


def _format_report(
    ledger_file: str, ledger: EvidenceLedger, as_json: bool, shadow_window: int | None = None
) -> tuple[str, bool]:
    """Render a ledger summary as the JSON object or the text table.

    Returns the text to print and whether the hash chain verified, so the
    one-shot report and the ``--watch`` loop format a ledger the same way.
    ``shadow_window`` bounds the recent agreement rate (see
    :meth:`EvidenceLedger.summary`).
    """
    ok = ledger.verify()
    summary = ledger.summary(shadow_window)
    if as_json:
        # The text table below hand-picks a subset of the summary; the JSON
        # carries every field a dashboard might chart, with chain validity and
        # the file it came from alongside it.
        payload = {"ledger_file": ledger_file, "chain_valid": ok, **asdict(summary)}
        return json.dumps(payload, indent=2) + "\n", ok
    agreement = "%.1f%%" % (summary.shadow_agreement_rate * 100.0) if summary.shadow_probes else "n/a"
    lines = [
        "Ledger file:         %s" % ledger_file,
        "Chain valid:         %s" % ok,
        "Requests:            %d" % summary.total,
        "Allowed:             %d" % summary.allowed,
        "Blocked by tier 1:   %d" % summary.blocked_by_tier1,
        "Blocked by tier 2:   %d" % summary.blocked_by_tier2,
        "Short-circuit rate:  %.0f%%" % (summary.short_circuit_rate * 100),
        "Tier-two cost spent: $%.6f" % summary.cost_incurred,
        "Tier-two cost saved: $%.6f" % summary.cost_saved,
        "Latency p50 / p95:   %.2f ms / %.2f ms" % (summary.latency_p50_ms, summary.latency_p95_ms),
        "Shadow probes:       %d" % summary.shadow_probes,
        "Shadow agreement:    %s" % agreement,
    ]
    # Only worth a second line when a window was asked for and the tail it names
    # is shorter than the whole run; otherwise it just repeats the figure above.
    if summary.shadow_window is not None and summary.recent_shadow_probes < summary.shadow_probes:
        lines.append(
            "Recent agreement:    %.1f%% (last %d)"
            % (summary.recent_shadow_agreement_rate * 100.0, summary.recent_shadow_probes)
        )
    return "\n".join(lines) + "\n", ok


def _poll_report(ledger_file: str, as_json: bool, shadow_window: int | None = None) -> str | None:
    """Read and render the ledger once, or None if it cannot be read right now.

    A file the writer has not created yet, or a line caught partway through an
    append, is not a watch-ending error: return None and let the caller retry.
    """
    try:
        rendered, _ = _format_report(ledger_file, EvidenceLedger.load(ledger_file), as_json, shadow_window)
    except (OSError, json.JSONDecodeError):
        return None
    return rendered


def watch_report(
    ledger_file: str,
    stdout: TextIO,
    *,
    as_json: bool = False,
    interval: float = 2.0,
    shadow_window: int | None = None,
    sleeper: Callable[[float], None] = time.sleep,
    max_polls: int | None = None,
) -> int:
    """Re-read a growing ledger and re-emit its summary whenever it changes.

    One long-running process a dashboard can poll, instead of re-invoking the
    CLI for each refresh. The ledger is re-read every *interval* seconds; the
    summary prints on the first successful read and again each time it differs
    from what was last shown, so an unchanged ledger is not reprinted. *sleeper*
    and *max_polls* are injected for tests; the CLI leaves the loop unbounded
    and stops on Ctrl-C.
    """
    last: str | None = None
    polls = 0
    try:
        while max_polls is None or polls < max_polls:
            rendered = _poll_report(ledger_file, as_json, shadow_window)
            if rendered is not None and rendered != last:
                stdout.write(rendered)
                stdout.flush()
                last = rendered
            polls += 1
            if max_polls is None or polls < max_polls:
                sleeper(interval)
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_report(args: argparse.Namespace, stdin: TextIO, stdout: TextIO) -> int:
    if args.watch:
        return watch_report(
            args.ledger_file, stdout, as_json=args.json, interval=args.interval, shadow_window=args.shadow_window
        )
    try:
        ledger = EvidenceLedger.load(args.ledger_file)
    except FileNotFoundError:
        sys.stderr.write(
            "report: ledger file not found: %s\n"
            "Write one first with `check --ledger %s`.\n" % (args.ledger_file, args.ledger_file)
        )
        return 2
    except (OSError, json.JSONDecodeError) as exc:
        sys.stderr.write("report: could not read ledger %s: %s\n" % (args.ledger_file, exc))
        return 2
    rendered, ok = _format_report(args.ledger_file, ledger, args.json, args.shadow_window)
    stdout.write(rendered)
    return 0 if ok else 1


def _cmd_lint(args: argparse.Namespace, stdin: TextIO, stdout: TextIO) -> int:
    # Lint output is the product here, so problems go to stdout (a CI log),
    # and any failure is exit 1: the gate either passes or it does not.
    try:
        spec = PolicySpec.from_file(args.policy_file)
    except (OSError, ValueError) as exc:
        stdout.write("FAIL: %s\n" % exc)
        return 1
    ledger = None
    if args.ledger:
        try:
            ledger = EvidenceLedger.load(args.ledger)
        except (OSError, ValueError) as exc:
            stdout.write("FAIL: could not load ledger %s: %s\n" % (args.ledger, exc))
            return 1
    problems = lint_policy(spec, required=args.require, ledger=ledger)
    if problems:
        for problem in problems:
            stdout.write("FAIL: %s\n" % problem)
        return 1
    count = len(args.require) if args.require else len(CONTROL_CATALOG)
    stdout.write("OK: policy %r v%s satisfies all %d required control(s)\n" % (spec.name, spec.version, count))
    return 0


def _cmd_card(args: argparse.Namespace, stdin: TextIO, stdout: TextIO) -> int:
    spec = _load_policy(args.policy)
    if spec is None:
        return 2
    ledger = None
    if args.ledger:
        try:
            ledger = EvidenceLedger.load(args.ledger)
        except (OSError, ValueError) as exc:
            sys.stderr.write("ledger error: %s\n" % exc)
            return 2
    card = system_card(spec, ledger)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(card)
        stdout.write("Wrote system card to %s\n" % args.output)
    else:
        stdout.write(card)
    # A card generated over a broken chain still prints (it says so in its
    # evidence table), but the exit code lets a pipeline refuse to publish it.
    return 1 if ledger is not None and not ledger.verify() else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail-cascade",
        description="Run the two-tier guardrail cascade, lint its policy, and report over its evidence ledger.",
    )
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("check", help="screen prompts read from stdin")
    check.add_argument("--single", action="store_true", help="treat all of stdin as one prompt, not one per line")
    check.add_argument("--json", action="store_true", help="emit the scrubbed ledger entry as JSON per prompt")
    check.add_argument("--ledger", metavar="PATH", help="append the evidence ledger to this JSON Lines file")
    check.add_argument("--policy", metavar="PATH", help="build the cascade from this policy file instead of defaults")
    check.add_argument(
        "--block-keyword",
        action="append",
        metavar="WORD",
        help="a tier-two block keyword for the offline stub provider (repeatable, adds to the policy's)",
    )
    check.add_argument(
        "--block-only",
        action="store_true",
        help="escalate every tier-one allow to tier two; only blocks short-circuit",
    )
    check.add_argument("--claude", action="store_true", help="use a Claude model as tier two (calls the paid API)")
    check.add_argument("--model", default="claude-haiku-5-5", help="the model --claude uses (default: %(default)s)")
    check.add_argument(
        "--fail-open", action="store_true", help="with --claude, let traffic through as FLAG if the API is down"
    )
    check.set_defaults(func=_cmd_check)

    report = sub.add_parser("report", help="summarize a ledger JSON Lines file")
    report.add_argument("ledger_file", help="path to a JSON Lines ledger written by `check --ledger`")
    report.add_argument("--json", action="store_true", help="emit the whole summary as one JSON object for a dashboard")
    report.add_argument(
        "--watch", action="store_true", help="keep re-reading the ledger and re-emit the summary as it grows"
    )
    report.add_argument(
        "--interval",
        type=float,
        default=2.0,
        metavar="SECONDS",
        help="seconds between re-reads with --watch (default: %(default)s)",
    )
    report.add_argument(
        "--shadow-window",
        type=int,
        default=None,
        metavar="N",
        help="also report shadow agreement over the last N probes, where drift shows before the lifetime rate does",
    )
    report.set_defaults(func=_cmd_report)

    lint = sub.add_parser("lint", help="fail (exit 1) when the policy misses a required governance control")
    lint.add_argument("policy_file", help="path to the policy file to lint")
    lint.add_argument(
        "--require",
        action="append",
        metavar="CONTROL_ID",
        help="a control id that must be satisfied (repeatable; default: every cataloged control)",
    )
    lint.add_argument("--ledger", metavar="PATH", help="also check evidence in this ledger file (e.g. chain validity)")
    lint.set_defaults(func=_cmd_lint)

    card = sub.add_parser("card", help="render the policy (and optional ledger) into a Markdown system card")
    card.add_argument("--policy", metavar="PATH", help="policy file to document (default: the built-in defaults)")
    card.add_argument("--ledger", metavar="PATH", help="ledger file supplying the operational evidence")
    card.add_argument("--output", "-o", metavar="PATH", help="write the card here instead of stdout")
    card.set_defaults(func=_cmd_card)

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
