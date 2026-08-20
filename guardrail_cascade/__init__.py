"""guardrail-cascade: a two-tier guardrail cascade with an evidence ledger.

Cheap heuristics run first and block only what they are sure about; whatever
gets through goes to a paid, model-based provider; and every decision is written
to a tamper-evident ledger that also tracks latency and cost. See the README for
the design and docs/ROADMAP.md for what is built incrementally on top.
"""

from guardrail_cascade.cascade import CascadePolicy, Decision, Tier, TierResult
from guardrail_cascade.core import Action, CheckResult, Guardrail
from guardrail_cascade.feedback import CandidateMiner, RuleProposal
from guardrail_cascade.governance import (
    CONTROL_CATALOG,
    Control,
    ControlAssessment,
    FrameworkRef,
    assess_controls,
    lint_policy,
    system_card,
)
from guardrail_cascade.heuristics import (
    PIIGuard,
    PromptInjectionGuard,
    SecretGuard,
    ToxicityGuard,
)
from guardrail_cascade.ledger import CostModel, EvidenceLedger, LedgerSummary
from guardrail_cascade.policy import DEFAULT_GUARDRAILS, GUARDRAIL_REGISTRY, PolicySpec, register_guardrail
from guardrail_cascade.providers import StubProvider, Tier2Provider
from guardrail_cascade.scrub import scrub

__all__ = [
    "Action",
    "CheckResult",
    "Guardrail",
    "Tier",
    "TierResult",
    "CascadePolicy",
    "Decision",
    "EvidenceLedger",
    "CostModel",
    "LedgerSummary",
    "Tier2Provider",
    "StubProvider",
    "SecretGuard",
    "PromptInjectionGuard",
    "PIIGuard",
    "ToxicityGuard",
    "CandidateMiner",
    "RuleProposal",
    "scrub",
    "PolicySpec",
    "GUARDRAIL_REGISTRY",
    "DEFAULT_GUARDRAILS",
    "register_guardrail",
    "Control",
    "ControlAssessment",
    "FrameworkRef",
    "CONTROL_CATALOG",
    "assess_controls",
    "lint_policy",
    "system_card",
]

__version__ = "0.2.0"
