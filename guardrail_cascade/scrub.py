"""Last-line masking for anything written to the evidence ledger.

The built-in guardrails only ever put structured labels in a ``CheckResult``
(``{"labels": ["EMAIL"]}``, not the address), so nothing sensitive reaches the
ledger from them. This module does not trust that. A custom guardrail, or a real
tier-two provider that returns the offending span, could place a raw email or
credential in a ``reason`` or ``detail`` field, and the ledger would otherwise
store it verbatim. :func:`scrub` masks PII and secret-shaped substrings in every
string the ledger persists, so the log does not depend on the caller getting it
right.

What it catches is the list in ``_PATTERNS`` and nothing else: emails, phone
numbers, SSNs, card numbers, and the credentials with a recognizable format
(AWS access key ids and secret keys, GitHub tokens, Google and OpenAI API keys,
Stripe live keys, JWTs, PEM private key headers). A credential format that is
not listed, and PII that has no shape at all such as a person's name, are not
masked. Read it as a net with a known mesh, not as a guarantee, and add the
shapes your own traffic carries.

Scrubbing runs on every ledger write regardless of which guardrails are in the
tier, so the log is masked even when no PII guardrail is configured. On PII it
is deliberately looser than :class:`guardrail_cascade.heuristics.PIIGuard`,
without the checksum and context checks, because masking a stray order id in a
log costs less than forwarding one to a paid provider. The secret shapes it
masks are :data:`SECRET_SHAPES`, the same list the guard blocks on, so the two
cannot drift apart.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SecretShape:
    """One credential shape, shared by the tier-one blocker and this scrubber.

    ``name`` is the label :class:`guardrail_cascade.heuristics.SecretGuard`
    reports when it blocks the shape. ``replacement`` is what the scrubber puts
    in the log: ``[SECRET]`` for every shape except the AWS secret access key,
    where the name that introduces the key is kept and only the value is masked.
    """

    name: str
    pattern: re.Pattern[str]
    replacement: str = "[SECRET]"


# The credential shapes, defined once. The tier-one SecretGuard reads this list
# to block them and the scrubber below reads it to mask them in the ledger, so a
# shape added here lands in both places and a key the guard blocks can never be
# one the log leaks (or the reverse).
SECRET_SHAPES: tuple[SecretShape, ...] = (
    SecretShape("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    SecretShape("github_token", re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{36,}\b")),
    SecretShape("openai_api_key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    SecretShape("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    SecretShape("stripe_key", re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b")),
    # Three base64url segments from the "eyJ" that every JWT header begins with,
    # so an id or access token in a field does not survive.
    SecretShape("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+")),
    # An AWS secret access key is 40 unremarkable base64 characters, recognizable
    # only next to the name that introduces it, which the replacement keeps.
    SecretShape(
        "aws_secret_access_key",
        re.compile(r"((?i:\baws_?secret_?access_?key\b)\s*[=:]\s*[\"\']?)([A-Za-z0-9/+=]{40})"),
        r"\g<1>[SECRET]",
    ),
    SecretShape("private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
)

# PII shapes, then every secret shape. scrub_text applies them in this order.
_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[EMAIL]"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE]"),
    (re.compile(r"\b\d{3}[-.\s]?\d{2}[-.\s]?\d{4}\b"), "[SSN]"),
    (re.compile(r"\b(?:\d{4}[-.\s]?){3}\d{4}\b"), "[CARD]"),
] + [(shape.pattern, shape.replacement) for shape in SECRET_SHAPES]


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
