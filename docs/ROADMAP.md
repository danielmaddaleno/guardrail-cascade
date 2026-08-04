# Roadmap

Built incrementally, one small and defensible change at a time. The scaffold
already ships the two-tier cascade, the four heuristic guardrails, the offline
provider, the hash-chained ledger with a cost and latency summary, the shadow
sampler, and the candidate miner. What follows is the order things get added.

## Near term

- **Async, off-path shadow sampling.** Today the shadow probe runs inline for
  simplicity. Move it to a background task so it never adds latency to a blocked
  request, and record the agreement rate over a window.
- **Provider adapters.** A thin `BedrockProvider` around the AWS Bedrock
  Guardrails API, and a local `LlamaGuardProvider`, both behind the existing
  `Tier2Provider` interface. Keep the offline stub as the default so CI stays
  credential-free.
- **Redaction from a real toolkit.** Let tier one delegate to a dedicated
  guardrails library (for example llm-guardrails-toolkit) behind the `Guardrail`
  interface, instead of the built-in patterns.
- **CLI.** A `guardrail-cascade check` command that reads prompts from stdin and
  prints decisions, plus `guardrail-cascade report` over a ledger file.

## Medium term

- **Ledger report renderer.** Turn `summary()` into a small HTML report: block
  rates per tier, cost saved over time, latency percentiles, shadow agreement.
- **Policy schema.** A typed policy object (which guardrails run, thresholds,
  shadow rate) loadable from YAML, so the deployed configuration is reviewable
  and versioned rather than hard-coded.
- **Learned tier 1.5.** A small, cheap classifier trained on tier-two labels
  plus shadow-sampled allows (to counter the selection bias documented in
  ARCHITECTURE.md), sitting between the heuristics and the paid tier.

## Later

- **External anchor for the ledger.** Publish or sign the head hash (for example
  a periodic signed checkpoint) so the chain resists an attacker with full write
  access, not only accidental edits. Today the chain detects tampering only for
  someone who cannot recompute every later hash forward.
- **Governance crosswalk (optional).** Tag each control with references to
  NIST AI RMF, ISO/IEC 42001, and EU AI Act articles, and generate a Model or
  System Card from the policy plus the ledger. Kept optional because its value
  depends on the target market.
- **Policy lint in CI.** A check that fails a build when a required control or
  evidence field is missing, so governance is enforced the way tests are.
