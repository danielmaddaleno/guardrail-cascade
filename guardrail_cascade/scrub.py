"""Last-line masking for anything written to the evidence ledger.

The built-in guardrails only ever put structured labels in a ``CheckResult``
(``{"labels": ["EMAIL"]}``, not the address), so nothing sensitive reaches the
ledger from them. This module does not trust that. A custom guardrail, or a real
tier-two provider that returns the offending span, could place a raw email or
credential in a ``reason`` or ``detail`` field, and the ledger would otherwise
store it verbatim. :func:`scrub` masks PII and secret-shaped substrings in every
string the ledger persists, so the audit log stays safe regardless of who
produced the entry.

The patterns are intentionally independent of the detection heuristics: the log
must be safe even when no PII guardrail is configured, so this net does not
depend on which guardrails are in the tier.
"""

from __future__ import annotations

import re
from typing import Any

_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE]"),
    (re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"), "[SSN]"),
    (re.compile(r"\b(?:\d{4}[-.\s]?){3}\d{4}\b"), "[CARD]"),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "[SECRET]"),
    (re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{36,}\b"), "[SECRET]"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[SECRET]"),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b"), "[SECRET]"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "[SECRET]"),
]


def scrub_text(text: str) -> str:
    """Mask PII and secret-shaped substrings in a single string."""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def scrub(value: Any) -> Any:
    """Recursively mask strings inside a value, leaving structure and numbers intact.

    Dicts, lists, and tuples are walked; strings are masked; everything else
    (numbers, booleans, ``None``) is returned unchanged. Tuples keep their type
    so a secret tucked inside one is masked instead of slipping through the net
    the way it would if only dicts and lists were walked.
    """
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {key: scrub(item) for key, item in value.items()}
    if isinstance(value, list):
        return [scrub(item) for item in value]
    if isinstance(value, tuple):
        return tuple(scrub(item) for item in value)
    return value
