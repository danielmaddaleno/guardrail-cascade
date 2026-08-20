"""Policy as code: the deployed cascade configuration as a typed, reviewable object.

Hard-coding which guardrails run, the shadow-sampling rate, and the price model
scatters governance decisions through application code where no reviewer sees
them change. :class:`PolicySpec` gathers them into one declarative object that
can be loaded from a JSON (or YAML, if pyyaml is installed) file, validated,
diffed in code review, and versioned like any other artifact. The spec is also
what the governance layer (:mod:`guardrail_cascade.governance`) assesses: each
control either is or is not present in the policy, and a CI gate can fail a
build whose policy dropped a required control.

The schema is deliberately closed: an unknown key is an error, not a silent
no-op, because a typo like ``shadow_smaple_rate`` that silently disables
sampling is exactly the failure a reviewed policy exists to prevent.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Callable

from guardrail_cascade.cascade import CascadePolicy, Tier
from guardrail_cascade.core import Guardrail
from guardrail_cascade.heuristics import PIIGuard, PromptInjectionGuard, SecretGuard, ToxicityGuard
from guardrail_cascade.ledger import CostModel, EvidenceLedger
from guardrail_cascade.providers import StubProvider, Tier2Provider

#: Guardrails a policy may name, keyed by class name. Extend with
#: :func:`register_guardrail` so a custom guardrail becomes addressable from a
#: policy file without editing this module.
GUARDRAIL_REGISTRY: dict[str, type[Guardrail]] = {
    "SecretGuard": SecretGuard,
    "PromptInjectionGuard": PromptInjectionGuard,
    "PIIGuard": PIIGuard,
    "ToxicityGuard": ToxicityGuard,
}

#: The tier-one lineup a policy gets when it does not say otherwise: the four
#: bundled heuristics, in the same escalating order the README documents.
DEFAULT_GUARDRAILS: tuple[str, ...] = ("SecretGuard", "PromptInjectionGuard", "PIIGuard", "ToxicityGuard")

_SPEC_KEYS = {
    "name",
    "version",
    "guardrails",
    "shadow_sample_rate",
    "block_keywords",
    "price_per_1k_tokens",
    "chars_per_token",
}


def register_guardrail(cls: type[Guardrail], name: str | None = None) -> type[Guardrail]:
    """Make *cls* addressable from a policy file under *name* (default: class name).

    Returns the class so it can be used as a decorator. Registering an existing
    name overwrites it, which lets a deployment swap a built-in for a stricter
    variant without renaming it in every policy file.
    """
    GUARDRAIL_REGISTRY[name or cls.__name__] = cls
    return cls


@dataclass
class PolicySpec:
    """The reviewable description of one deployed cascade.

    ``guardrails`` names the tier-one lineup in execution order, resolved
    against :data:`GUARDRAIL_REGISTRY`. ``block_keywords`` configures the
    offline stub used when no real tier-two provider is wired in, so a policy
    file is runnable as-is in CI. The two cost fields feed the
    :class:`~guardrail_cascade.ledger.CostModel` that prices what a
    short-circuit saved.
    """

    name: str = "default"
    version: str = "1"
    guardrails: list[str] = field(default_factory=lambda: list(DEFAULT_GUARDRAILS))
    shadow_sample_rate: float = 0.0
    block_keywords: list[str] = field(default_factory=list)
    price_per_1k_tokens: float = 0.003
    chars_per_token: float = 4.0

    @classmethod
    def from_dict(cls, data: dict) -> "PolicySpec":
        """Build a spec from a parsed mapping, rejecting unknown keys.

        Unknown keys raise ``ValueError`` naming every offender at once: a
        misspelled field that silently fell back to a default would defeat the
        point of reviewing the policy. Value problems (an unregistered
        guardrail, an out-of-range rate) are reported by :meth:`validate`
        instead, so a linter can list them all rather than stopping at the
        first.
        """
        if not isinstance(data, dict):
            raise ValueError("a policy must be a mapping of fields, got %s" % type(data).__name__)
        # Keys are stringified before sorting: a YAML mapping can carry
        # non-string keys, and a mixed-type sort would raise TypeError instead
        # of this error naming the offenders.
        unknown = sorted(str(key) for key in set(data) - _SPEC_KEYS)
        if unknown:
            raise ValueError(
                "unknown policy field(s): %s (known fields: %s)" % (", ".join(unknown), ", ".join(sorted(_SPEC_KEYS)))
            )
        return cls(**data)

    @classmethod
    def from_file(cls, path: str) -> "PolicySpec":
        """Load a spec from a JSON file, or a YAML file when pyyaml is available.

        JSON needs nothing beyond the standard library, so the CI path stays
        dependency-free; YAML is recognized by extension (``.yaml`` / ``.yml``)
        and asks for the optional dependency by name when it is missing.
        """
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        if path.endswith((".yaml", ".yml")):
            try:
                import yaml  # type: ignore[import-untyped]
            except ImportError as exc:
                raise ValueError(
                    "reading a YAML policy requires the optional pyyaml dependency "
                    "(pip install 'guardrail-cascade[yaml]'); JSON policies need nothing extra"
                ) from exc
            data = yaml.safe_load(text)
        else:
            try:
                data = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ValueError("policy file %s is not valid JSON: %s" % (path, exc)) from exc
        return cls.from_dict(data)

    def to_dict(self) -> dict:
        """The spec as a plain mapping, round-trippable through :meth:`from_dict`."""
        return {
            "name": self.name,
            "version": self.version,
            "guardrails": list(self.guardrails),
            "shadow_sample_rate": self.shadow_sample_rate,
            "block_keywords": list(self.block_keywords),
            "price_per_1k_tokens": self.price_per_1k_tokens,
            "chars_per_token": self.chars_per_token,
        }

    def validate(self) -> list[str]:
        """Return every problem with the spec, empty when it is deployable.

        Returning the full list rather than raising on the first problem is
        what lets ``guardrail-cascade lint`` show a reviewer everything wrong
        with a policy in one run.
        """
        problems: list[str] = []
        if not isinstance(self.name, str) or not self.name.strip():
            problems.append("name must be a non-empty string")
        if not isinstance(self.version, str) or not self.version.strip():
            problems.append("version must be a non-empty string")

        if not isinstance(self.guardrails, list) or any(not isinstance(g, str) for g in self.guardrails):
            problems.append("guardrails must be a list of guardrail names")
        else:
            for guard in self.guardrails:
                if guard not in GUARDRAIL_REGISTRY:
                    problems.append(
                        "unknown guardrail %r (registered: %s)" % (guard, ", ".join(sorted(GUARDRAIL_REGISTRY)))
                    )
            duplicates = sorted({g for g in self.guardrails if self.guardrails.count(g) > 1})
            if duplicates:
                problems.append("duplicate guardrail(s): %s" % ", ".join(duplicates))

        if not isinstance(self.shadow_sample_rate, (int, float)) or isinstance(self.shadow_sample_rate, bool):
            problems.append("shadow_sample_rate must be a number between 0 and 1")
        elif not 0.0 <= float(self.shadow_sample_rate) <= 1.0:
            problems.append("shadow_sample_rate must be between 0 and 1, got %s" % self.shadow_sample_rate)

        if not isinstance(self.block_keywords, list) or any(
            not isinstance(k, str) or not k.strip() for k in self.block_keywords
        ):
            problems.append("block_keywords must be a list of non-empty strings")

        if not isinstance(self.price_per_1k_tokens, (int, float)) or self.price_per_1k_tokens < 0:
            problems.append("price_per_1k_tokens must be a non-negative number")
        if not isinstance(self.chars_per_token, (int, float)) or self.chars_per_token <= 0:
            problems.append("chars_per_token must be a positive number")
        return problems

    def build_tier1(self) -> Tier:
        """Instantiate the named guardrails, in order, as the tier-one stage."""
        return Tier("heuristics", [GUARDRAIL_REGISTRY[name]() for name in self.guardrails])

    def build_cost_model(self) -> CostModel:
        return CostModel(price_per_1k_tokens=self.price_per_1k_tokens, chars_per_token=self.chars_per_token)

    def build(
        self,
        tier2: Tier2Provider | None = None,
        ledger: EvidenceLedger | None = None,
        *,
        sampler: Callable[[], float] | None = None,
        clock: Callable[[], float] | None = None,
    ) -> CascadePolicy:
        """Wire the whole cascade this spec describes and return it ready to serve.

        ``tier2`` defaults to the offline :class:`StubProvider` configured with
        the spec's ``block_keywords``, so a policy file alone yields a runnable,
        credential-free cascade; a real deployment passes its provider adapter.
        Raises ``ValueError`` when :meth:`validate` finds problems, so an
        invalid policy cannot be deployed by accident.
        """
        problems = self.validate()
        if problems:
            raise ValueError("policy %r is not deployable: %s" % (self.name, "; ".join(problems)))
        extras: dict[str, Any] = {}
        if sampler is not None:
            extras["sampler"] = sampler
        if clock is not None:
            extras["clock"] = clock
        return CascadePolicy(
            self.build_tier1(),
            tier2 if tier2 is not None else StubProvider(block_keywords=list(self.block_keywords)),
            ledger if ledger is not None else EvidenceLedger(),
            cost_model=self.build_cost_model(),
            shadow_sample_rate=float(self.shadow_sample_rate),
            **extras,
        )
