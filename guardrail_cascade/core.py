"""Core abstractions shared by every tier of the cascade.

A :class:`Guardrail` inspects a piece of text and returns a :class:`CheckResult`
naming one of four actions, ordered from least to most severe:

- ``ALLOW``  : nothing found.
- ``FLAG``   : suspicious on a fuzzy signal. On its own it never blocks; it
  marks the request for escalation to the next tier and for sampling. This is
  what keeps a noisy heuristic (toxicity keywords, say) from silently blocking
  legitimate traffic.
- ``REDACT`` : a high-precision match that can be masked in place. The text is
  forwarded with the match replaced by a label.
- ``BLOCK``  : a high-precision match that must stop the request.

The split between ``BLOCK`` and ``FLAG`` is the whole point of tier one: block
only what we are confident about, and flag the rest instead of over-blocking.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum


class Action(IntEnum):
    """Guardrail outcomes, ordered by severity so they can be compared.

    The integer ordering lets a tier pick the most severe action across its
    guardrails with a plain ``max(...)``.
    """

    ALLOW = 0
    FLAG = 1
    REDACT = 2
    BLOCK = 3


@dataclass(frozen=True)
class CheckResult:
    """The outcome of a single guardrail run.

    ``output`` carries the transformed text when ``action`` is ``REDACT`` and is
    ``None`` otherwise. ``detail`` holds structured context (which categories
    fired, how many) but never the raw matched value, so a result is always safe
    to write to the evidence ledger.
    """

    guardrail: str
    action: Action
    reason: str = ""
    output: str | None = None
    detail: dict = field(default_factory=dict)


class Guardrail(ABC):
    """A cheap, synchronous check over a piece of text.

    Concrete guardrails live in :mod:`guardrail_cascade.heuristics`. Anything
    implementing ``check(text) -> CheckResult`` can join a tier, including an
    adapter around an existing toolkit.
    """

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    def check(self, text: str) -> CheckResult:
        """Inspect *text* and return a :class:`CheckResult`."""
        raise NotImplementedError
