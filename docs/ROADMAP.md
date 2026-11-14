# Roadmap

Built incrementally, one small and defensible change at a time. Shipped so far:
the two-tier cascade, the four heuristic guardrails, the offline provider and a
Claude provider, the hash-chained ledger with a cost, latency and
shadow-agreement summary, the shadow sampler (inline or off-path through an
injected executor), the block-only short-circuit
option, the candidate miner, the command-line interface (`check`,
`report` with a `--json` summary and a `--watch` mode that reprints as the
ledger grows, `lint`, `card`), and the governance layer: a typed policy schema
loadable from JSON (YAML with the optional extra), a control catalog
crosswalked to NIST AI RMF, ISO/IEC 42001 and the EU AI Act, a policy lint
gate wired into this repo's own CI, and a system card generated from the
policy plus the ledger. What follows is the order things get added.

## Near term

- **Off-path shadow sampling.** Done at the library level: pass a
  `shadow_executor` to `CascadePolicy` and the audit probe and its ledger write
  run on that executor instead of the request thread, so sampling never holds
  the caller for the paid round trip. The windowed view it feeds is here too:
  `summary` takes a `shadow_window` and `report --shadow-window N` prints the
  agreement rate over the last N probes, where drift shows before the lifetime
  rate does. Left to do: surface it in the `check` CLI, which would need to drain
  pending probes before the process exits.
- **More provider adapters.** `ClaudeProvider` shipped. Next are a thin
  `BedrockProvider` around the AWS Bedrock Guardrails API and a local
  `LlamaGuardProvider`, behind the same `Tier2Provider` interface. Keep the
  offline stub as the default so CI stays credential-free.
- **Redaction from a real toolkit.** Let tier one delegate to a dedicated
  guardrails library (for example llm-guardrails-toolkit) behind the `Guardrail`
  interface, instead of the built-in patterns.
- **Push the watch feed somewhere.** `report --watch` re-reads a growing ledger
  and reprints the summary from one process. The next step is to emit each
  refresh over a socket or to an endpoint, so a dashboard subscribes instead of
  tailing stdout.

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
