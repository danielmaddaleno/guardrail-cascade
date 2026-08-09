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


class PIIGuard(Guardrail):
    """REDACT common PII in place and forward the masked text."""

    PATTERNS = {
        "EMAIL": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "PHONE": r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        "SSN": r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b",
    }

    def __init__(self) -> None:
        self._compiled = {label: re.compile(pattern) for label, pattern in self.PATTERNS.items()}

    def check(self, text: str) -> CheckResult:
        masked = text
        hit_labels = []
        for label, pattern in self._compiled.items():
            masked, count = pattern.subn("[" + label + "]", masked)
            if count:
                hit_labels.append(label)
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
