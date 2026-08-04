"""Tier-two providers: the paid, model-based barrier behind the heuristics.

The cascade only calls a provider for traffic that tier one did not already
block, so this is the expensive stage we are trying to hit less often. The
provider is an interface with a single method, so a real deployment can drop in
AWS Bedrock Guardrails, Llama Guard, or an internal service without touching the
cascade. :class:`StubProvider` is a deterministic, offline stand-in so the whole
pipeline runs in CI with no credentials.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from guardrail_cascade.core import Action, CheckResult


class Tier2Provider(ABC):
    """A model-based guardrail reached over the network in production."""

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @abstractmethod
    def check(self, text: str) -> CheckResult:
        """Return a verdict for *text*. Blocks are the expensive catches."""
        raise NotImplementedError


class StubProvider(Tier2Provider):
    """Deterministic offline provider used for demos and tests.

    It blocks when the text contains any configured keyword (case-insensitive),
    which lets a test model a tier-two catch that the heuristics missed. It never
    reaches the network, so it is safe to run anywhere. Swap it for a Bedrock or
    Llama Guard adapter in a real deployment; see docs/ROADMAP.md.
    """

    def __init__(self, block_keywords: list[str] | None = None):
        self.block_keywords = [k.lower() for k in (block_keywords or [])]

    def check(self, text: str) -> CheckResult:
        lowered = text.lower()
        for keyword in self.block_keywords:
            if keyword in lowered:
                return CheckResult(
                    guardrail=self.name,
                    action=Action.BLOCK,
                    reason="matched a tier-two policy category",
                    detail={"category": keyword},
                )
        return CheckResult(guardrail=self.name, action=Action.ALLOW)
