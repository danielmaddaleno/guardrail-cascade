"""Tier-one guardrails: cheap, precompiled, high-precision heuristics.

These are deliberately conservative. Two of them BLOCK (secrets and the clear
injection phrases) because a match is almost never a false positive. One REDACTs
(PII) because the safe move is to mask and forward. One only FLAGs (toxicity)
because keyword matching is noisy, and flagging escalates to tier two instead of
blocking a possibly innocent message.

In a real deployment tier one would be backed by a dedicated toolkit (for
example llm-guardrails-toolkit) plugged in behind the same ``Guardrail``
interface. These built-ins keep the package self-contained and runnable.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable

from guardrail_cascade.core import Action, CheckResult, Guardrail


class SecretGuard(Guardrail):
    """BLOCK text that carries what looks like a live credential.

    Targets structured, prefixed secrets whose format is fixed, so a match is
    high confidence. The matched value is never returned in the result, so the
    guard does not become a second place the secret leaks.

    These shapes are kept in step with the secret patterns in
    :mod:`guardrail_cascade.scrub`. The scrubber is the last line for the audit
    log, but it only runs once an entry is being written: a key shape it knows
    and this guard does not is one that gets forwarded to the paid tier before
    anything masks it.
    """

    PATTERNS = {
        "aws_access_key_id": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
        "github_token": r"\bgh[oprsu]_[A-Za-z0-9]{36,}\b",
        "openai_api_key": r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",
        "google_api_key": r"\bAIza[0-9A-Za-z_-]{35}\b",
        "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----",
    }

    def __init__(self) -> None:
        self._compiled = {name: re.compile(pattern) for name, pattern in self.PATTERNS.items()}

    def check(self, text: str) -> CheckResult:
        found = [name for name, pattern in self._compiled.items() if pattern.search(text)]
        if found:
            return CheckResult(
                guardrail=self.name,
                action=Action.BLOCK,
                reason="credential-like secret detected",
                detail={"kinds": found},
                # A matched secret must never be forwarded, so this block is
                # excluded from shadow sampling to the paid tier.
                sensitive=True,
            )
        return CheckResult(guardrail=self.name, action=Action.ALLOW)


class PromptInjectionGuard(Guardrail):
    """BLOCK the clearest instruction-override phrases.

    Only canonical, high-precision phrasings are listed. Paraphrased or subtle
    attempts are out of scope on purpose: those belong to tier two, or to a FLAG
    rule, not to a hard block.
    """

    PATTERNS = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(all\s+)?(previous|prior)\s+instructions",
        r"forget\s+(everything|all)\s+(above|previous)",
        r"reveal\s+(the\s+)?system\s*prompt",
    ]

    def __init__(self) -> None:
        self._compiled = [re.compile(pattern, re.IGNORECASE) for pattern in self.PATTERNS]

    def check(self, text: str) -> CheckResult:
        hits = [pattern.pattern for pattern in self._compiled if pattern.search(text)]
        if hits:
            return CheckResult(
                guardrail=self.name,
                action=Action.BLOCK,
                reason="prompt injection phrase detected",
                detail={"count": len(hits)},
            )
        return CheckResult(guardrail=self.name, action=Action.ALLOW)


def _digits(text: str) -> str:
    return "".join(char for char in text if char.isdigit())


def _luhn_ok(value: str) -> bool:
    """True if the digits in *value* satisfy the Luhn checksum cards carry."""
    digits = _digits(value)
    total = 0
    for position, char in enumerate(reversed(digits)):
        digit = int(char)
        if position % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


@dataclass(frozen=True)
class _PIIRule:
    """One PII shape: where to look, what to mask, and how to confirm it.

    ``group`` names the part of the match to replace, so a rule can use nearby
    words as context without masking them too. ``confirm`` is an extra check on
    the matched value for shapes a regex cannot settle on its own.
    """

    label: str
    pattern: re.Pattern[str]
    group: int = 0
    confirm: Callable[[str], bool] | None = None


def _mask_rule(rule: _PIIRule, text: str) -> tuple[str, bool]:
    """Replace every confirmed match of *rule* with its label."""
    hits = 0

    def replace(match: re.Match[str]) -> str:
        nonlocal hits
        whole = match.group(0)
        value = match.group(rule.group)
        if rule.confirm is not None and not rule.confirm(value):
            return whole
        hits += 1
        start = match.start(rule.group) - match.start(0)
        end = match.end(rule.group) - match.start(0)
        return whole[:start] + "[" + rule.label + "]" + whole[end:]

    masked = rule.pattern.sub(replace, text)
    return masked, hits > 0


class PIIGuard(Guardrail):
    """REDACT common PII in place and forward the masked text.

    A bare run of digits is an order id, a build number or a primary key far
    more often than it is an SSN or a phone number, and masking one costs twice:
    a REDACT escalates to the paid tier, and the model downstream reads a hole
    where the id was. So the digit rules ask for more than a length. An SSN or a
    phone number needs separators or a labeling word next to it, and a card
    number has to pass the Luhn checksum.

    The card shape is kept in step with the ledger scrubber in
    :mod:`guardrail_cascade.scrub`, which masks the same shape without the
    checksum. They only diverge on a number that is not a card, and the log is
    where over-masking is the cheap mistake.
    """

    RULES: tuple[_PIIRule, ...] = (
        _PIIRule("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
        _PIIRule("CARD", re.compile(r"(?<!\d)(?:\d{4}[-.\s]?){3}\d{4}(?!\d)"), confirm=_luhn_ok),
        # Separated: the writer already grouped the digits the way an SSN is written.
        _PIIRule("SSN", re.compile(r"(?<!\d)\d{3}([-.\s])\d{2}\1\d{4}(?!\d)")),
        # Bare nine digits, but only right after a word that says what they are.
        _PIIRule(
            "SSN",
            re.compile(r"\b(?:ssn|social security(?: number)?)\b\D{0,12}((?<!\d)\d{9}(?!\d))", re.IGNORECASE),
            group=1,
        ),
        _PIIRule("PHONE", re.compile(r"(?<!\d)(?:\+1[-.\s]?)?(?:\(\d{3}\)[-.\s]?|\d{3}[-.\s])\d{3}[-.\s]?\d{4}(?!\d)")),
        _PIIRule(
            "PHONE",
            re.compile(r"\b(?:phone|tel|telephone|mobile|cell)\b\D{0,12}((?<!\d)\d{10}(?!\d))", re.IGNORECASE),
            group=1,
        ),
    )

    def check(self, text: str) -> CheckResult:
        masked = text
        hit_labels: list[str] = []
        for rule in self.RULES:
            masked, hit = _mask_rule(rule, masked)
            if hit and rule.label not in hit_labels:
                hit_labels.append(rule.label)
        if hit_labels:
            return CheckResult(
                guardrail=self.name,
                action=Action.REDACT,
                reason="masked PII before forwarding",
                output=masked,
                detail={"labels": hit_labels},
            )
        return CheckResult(guardrail=self.name, action=Action.ALLOW)


class ToxicityGuard(Guardrail):
    """FLAG toxic-looking text so it escalates instead of being blocked.

    Keyword matching is noisy, so this never blocks on its own. A FLAG tells the
    cascade to lean on tier two and marks the request for sampling.
    """

    CATEGORIES = {
        "hate": [r"\bracis[tm]\b", r"\bsexis[tm]\b", r"\bhomophobi[ac]\b"],
        "violence": [r"\bkill\s+(him|her|them|you)\b", r"\bbomb\s+threat\b"],
    }

    def __init__(self) -> None:
        self._compiled = {
            category: [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
            for category, patterns in self.CATEGORIES.items()
        }

    def check(self, text: str) -> CheckResult:
        hits = [category for category, patterns in self._compiled.items() if any(p.search(text) for p in patterns)]
        if hits:
            return CheckResult(
                guardrail=self.name,
                action=Action.FLAG,
                reason="possible toxic content, escalating",
                detail={"categories": hits},
            )
        return CheckResult(guardrail=self.name, action=Action.ALLOW)
