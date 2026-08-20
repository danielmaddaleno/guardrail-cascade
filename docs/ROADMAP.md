# Roadmap

Built incrementally, one small and defensible change at a time. Shipped so far:
the two-tier cascade, the four heuristic guardrails, the offline provider, the
hash-chained ledger with a cost, latency and shadow-agreement summary, the
shadow sampler, the candidate miner, the command-line interface (`check`,
`report`, `lint`, `card`), and the governance layer: a typed policy schema
loadable from JSON (YAML with the optional extra), a control catalog
crosswalked to NIST AI RMF, ISO/IEC 42001 and the EU AI Act, a policy lint
gate wired into this repo's own CI, and a system card generated from the
policy plus the ledger. What follows is the order things get added.

## Near term

- **Async, off-path shadow sampling.** Today the shadow probe runs inline for
  simplicity. Move it to a background task so it never adds latency to a blocked
  request, and report the agreement rate over a sliding window rather than only
  cumulatively.
- **Provider adapters.** A thin `BedrockProvider` around the AWS Bedrock
  Guardrails API, and a local `LlamaGuardProvider`, both behind the existing
  `Tier2Provider` interface. Keep the offline stub as the default so CI stays
  credential-free.
- **Redaction from a real toolkit.** Let tier one delegate to a dedicated
  guardrails library (for example llm-guardrails-toolkit) behind the `Guardrail`
  interface, instead of the built-in patterns.
- **JSON report output.** `check --policy`, `lint` and `card` ship now; next is
  `report --json` so the ledger summary feeds a dashboard directly.

## Medium term

- **Ledger report renderer.** Turn `summary()` into a small HTML report: block
  rates per tier, cost saved over time, latency percentiles, shadow agreement.
- **Learned tier 1.5.** A small, cheap classifier trained on tier-two labels
  plus shadow-sampled allows (to counter the selection bias documented in
  ARCHITECTURE.md), sitting between the heuristics and the paid tier.

## Later

- **External anchor for the ledger.** Publish or sign the head hash (for example
  a periodic signed checkpoint) so the chain resists an attacker with full write
  access, not only accidental edits. Today the chain detects tampering only for
  someone who cannot recompute every later hash forward.
- **Finer crosswalk granularity.** The control catalog cites NIST AI RMF at the
  function level and ISO/IEC 42001 at the clause level on purpose (a wrong
  subcategory is worse than a coarse right one); deepen to subcategories and
  Annex A controls once each mapping can be justified line by line.
