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
