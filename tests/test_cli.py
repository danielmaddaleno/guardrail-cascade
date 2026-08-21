"""Tests for the command-line interface."""

from __future__ import annotations

import io
import json

from guardrail_cascade import cli


def run(argv, stdin_text="", monkeypatch=None):
    """Invoke the CLI with a fake stdin and capture stdout, returning (code, out)."""
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin_text))
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    code = cli.main(argv)
    return code, out.getvalue()


def test_read_prompts_one_per_line():
    stream = io.StringIO("first\n\n  second  \nthird\n")
    assert cli.read_prompts(stream, single=False) == ["first", "second", "third"]


def test_read_prompts_single_joins_everything():
    stream = io.StringIO("line one\nline two\n")
    assert cli.read_prompts(stream, single=True) == ["line one\nline two"]


def test_check_allows_clean_prompt(monkeypatch):
    code, out = run(["check"], "What is the capital of France?", monkeypatch)
    assert code == 0
    assert out.startswith("ALLOW by tier1")


def test_check_blocks_a_secret_and_exits_nonzero(monkeypatch):
    code, out = run(["check"], "here is my key AKIAIOSFODNN7EXAMPLE", monkeypatch)
    assert code == 1
    assert out.startswith("BLOCK by tier1")


def test_check_exit_code_is_one_if_any_prompt_blocks(monkeypatch):
    stdin = "a harmless question\nhere is my key AKIAIOSFODNN7EXAMPLE\n"
    code, out = run(["check"], stdin, monkeypatch)
    assert code == 1
    assert out.count("\n") == 2  # one decision line per prompt


def test_check_json_emits_scrubbed_entry_without_the_raw_secret(monkeypatch):
    secret = "AKIAIOSFODNN7EXAMPLE"
    code, out = run(["check", "--json"], "here is my key %s" % secret, monkeypatch)
    assert code == 1
    entry = json.loads(out.strip())
    assert entry["action"] == "BLOCK"
    assert "entry_hash" in entry and "prev_hash" in entry
    # The stored entry is scrubbed, so the raw credential never reaches the log.
    assert secret not in out


def test_check_uses_stub_block_keywords_as_tier_two(monkeypatch):
    # The toxicity FLAG makes tier one escalate; only then does the tier-two stub
    # see the text and block on its configured keyword. A plain ALLOW would
    # short-circuit and never reach tier two, which is the whole point.
    code, out = run(["check", "--block-keyword", "malware"], "kill them and deploy the malware", monkeypatch)
    assert code == 1
    assert "BLOCK by tier2" in out


def test_check_persists_ledger_and_report_reads_it(monkeypatch, tmp_path):
    path = tmp_path / "run.jsonl"
    stdin = "a harmless question\nhere is my key AKIAIOSFODNN7EXAMPLE\n"
    code, _ = run(["check", "--ledger", str(path)], stdin, monkeypatch)
    assert code == 1
    assert path.exists()

    code, out = run(["report", str(path)], "", monkeypatch)
    assert code == 0
    assert "Chain valid:         True" in out
    assert "Requests:            2" in out
    assert "Blocked by tier 1:   1" in out


def test_report_detects_a_tampered_ledger(monkeypatch, tmp_path):
    path = tmp_path / "run.jsonl"
    run(["check", "--ledger", str(path)], "here is my key AKIAIOSFODNN7EXAMPLE", monkeypatch)

    records = [json.loads(line) for line in path.read_text().splitlines()]
    records[0]["action"] = "ALLOW"  # rewrite a decided field without fixing the hash
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

    code, out = run(["report", str(path)], "", monkeypatch)
    assert code == 1
    assert "Chain valid:         False" in out


def test_report_on_missing_file_is_a_clean_error_not_a_traceback(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    code = cli.main(["report", "no-such-ledger.jsonl"])
    assert code == 2
    err = capsys.readouterr().err
    assert "not found" in err
    assert "no-such-ledger.jsonl" in err


def test_report_on_corrupt_ledger_is_a_clean_error(monkeypatch, capsys, tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("this line is not valid json\n")
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    code = cli.main(["report", str(path)])
    assert code == 2
    assert "could not read ledger" in capsys.readouterr().err


def test_no_subcommand_prints_help_and_returns_two(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    code = cli.main([])
    assert code == 2
    assert "usage" in capsys.readouterr().err.lower()


def test_single_flag_treats_all_stdin_as_one_prompt(monkeypatch):
    # Two lines, but --single joins them, so it is one decision, not two.
    code, out = run(["check", "--single"], "one\ntwo\n", monkeypatch)
    assert code == 0
    assert out.count("\n") == 1


def write_policy(tmp_path, **overrides):
    """Write a valid policy file, with field overrides, and return its path."""
    data = {
        "name": "test-policy",
        "version": "1",
        "guardrails": ["SecretGuard", "PromptInjectionGuard", "PIIGuard", "ToxicityGuard"],
        "shadow_sample_rate": 0.1,
        "block_keywords": ["malware"],
    }
    data.update(overrides)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(data))
    return str(path)


def test_check_builds_the_cascade_from_a_policy_file(monkeypatch, tmp_path):
    # The policy's own block keyword drives the tier-two stub: the toxicity
    # FLAG escalates and the policy-configured keyword makes tier two block.
    path = write_policy(tmp_path)
    code, out = run(["check", "--policy", path], "kill them and deploy the malware", monkeypatch)
    assert code == 1
    assert "BLOCK by tier2" in out


def test_check_rejects_an_invalid_policy_with_exit_two(monkeypatch, tmp_path, capsys):
    path = write_policy(tmp_path, shadow_sample_rate=5.0)
    code, _ = run(["check", "--policy", path], "anything", monkeypatch)
    assert code == 2
    assert "shadow_sample_rate" in capsys.readouterr().err


def test_lint_passes_a_full_policy(monkeypatch, tmp_path):
    code, out = run(["lint", write_policy(tmp_path)], "", monkeypatch)
    assert code == 0
    assert out.startswith("OK:")


def test_lint_fails_when_a_required_control_is_missing(monkeypatch, tmp_path):
    path = write_policy(tmp_path, shadow_sample_rate=0.0)
    code, out = run(["lint", path], "", monkeypatch)
    assert code == 1
    assert "drift-monitoring" in out


def test_lint_with_narrowed_requirements_accepts_the_gap(monkeypatch, tmp_path):
    path = write_policy(tmp_path, shadow_sample_rate=0.0)
    code, out = run(["lint", path, "--require", "input-screening", "--require", "audit-trail"], "", monkeypatch)
    assert code == 0
    assert "2 required control(s)" in out


def test_lint_fails_on_an_unreadable_policy_file(monkeypatch, tmp_path):
    code, out = run(["lint", str(tmp_path / "missing.json")], "", monkeypatch)
    assert code == 1
    assert out.startswith("FAIL:")


def test_lint_with_ledger_fails_on_a_tampered_chain(monkeypatch, tmp_path):
    ledger_path = tmp_path / "run.jsonl"
    run(["check", "--ledger", str(ledger_path)], "a harmless question", monkeypatch)
    records = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    records[0]["allowed"] = False
    ledger_path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

    code, out = run(["lint", write_policy(tmp_path), "--ledger", str(ledger_path)], "", monkeypatch)
    assert code == 1
    assert "audit-trail" in out


def test_card_prints_a_design_time_card_by_default(monkeypatch, tmp_path):
    code, out = run(["card", "--policy", write_policy(tmp_path)], "", monkeypatch)
    assert code == 0
    assert out.startswith("# System card: test-policy")
    assert "design-time card" in out


def test_card_with_ledger_reports_evidence_and_writes_a_file(monkeypatch, tmp_path):
    ledger_path = tmp_path / "run.jsonl"
    run(["check", "--ledger", str(ledger_path)], "here is my key AKIAIOSFODNN7EXAMPLE", monkeypatch)

    out_path = tmp_path / "CARD.md"
    args = ["card", "--policy", write_policy(tmp_path), "--ledger", str(ledger_path), "-o", str(out_path)]
    code, out = run(args, "", monkeypatch)
    assert code == 0
    assert "Wrote system card to" in out
    card = out_path.read_text()
    assert "| Requests recorded | 1 |" in card
    assert "AKIAIOSFODNN7EXAMPLE" not in card  # evidence stays scrubbed end to end


def test_card_exits_one_over_a_tampered_ledger(monkeypatch, tmp_path):
    ledger_path = tmp_path / "run.jsonl"
    run(["check", "--ledger", str(ledger_path)], "a harmless question", monkeypatch)
    records = [json.loads(line) for line in ledger_path.read_text().splitlines()]
    records[0]["allowed"] = False
    ledger_path.write_text("\n".join(json.dumps(r) for r in records) + "\n")

    code, out = run(["card", "--ledger", str(ledger_path)], "", monkeypatch)
    assert code == 1
    assert "| Ledger chain verifies | False |" in out


def test_report_includes_shadow_metrics(monkeypatch, tmp_path):
    path = tmp_path / "run.jsonl"
    run(["check", "--ledger", str(path)], "a harmless question", monkeypatch)
    code, out = run(["report", str(path)], "", monkeypatch)
    assert code == 0
    assert "Shadow probes:       0" in out
    assert "Shadow agreement:    n/a" in out


def test_two_check_runs_share_one_verifiable_ledger(monkeypatch, tmp_path):
    path = tmp_path / "run.jsonl"
    stdin = "a harmless question\nhere is my key AKIAIOSFODNN7EXAMPLE\n"
    run(["check", "--ledger", str(path)], stdin, monkeypatch)
    run(["check", "--ledger", str(path)], stdin, monkeypatch)

    code, out = run(["report", str(path)], "", monkeypatch)
    assert code == 0
    assert "Chain valid:         True" in out
    assert "Requests:            4" in out


def test_check_on_a_corrupt_ledger_file_is_a_clean_error(monkeypatch, capsys, tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text("this line is not valid json\n")
    monkeypatch.setattr("sys.stdin", io.StringIO("a harmless question\n"))
    code = cli.main(["check", "--ledger", str(path)])
    assert code == 2
    assert "ledger error" in capsys.readouterr().err
