# GuardianTx — Architecture (Phase 1 baseline)

GuardianTx analyzes an Ethereum transaction **before the user signs it** and
returns a risk decision: `ALLOW` / `WARN` / `BLOCK` / `ESCALATE`.

Phase 1 ships the **non-agentic baseline** (deterministic tools + rules). The
proposed LLM agent (Phase 2) sits *on top of* the same tools and is measured
against this baseline.

## Data flow

```
                         Transaction (to, data, value, from, context)
                                        |
                                        v
                             +---------------------+
                             |   decoder (tool)    |  selector DB + static-word decode
                             +----------+----------+
                                        | DecodedCall(function, args, known?)
                   (optional)           v
        +------------------+   +---------------------+
        | simulator (tool) |-->|   rules engine      |  heuristics -> Finding[]
        | anvil / eth_call |   |  (baseline scorer)  |  noisy-OR -> score
        +------------------+   +----------+----------+
                                        | RiskReport(score, decision, findings)
                   (optional)           v
                             +---------------------+
                             |  llm explainer      |  provider setup + injection
                             |  (agent seed)       |  sanitation of untrusted text
                             +----------+----------+
                                        v
                          ALLOW / WARN / BLOCK / ESCALATE  (+ rationale)
```

## Structured contracts (`guardiantx/contracts.py`)

| Object        | Role                                                            |
|---------------|----------------------------------------------------------------|
| `Transaction` | the pre-signing request + optional wallet context              |
| `DecodedCall` | decoder output: function, named args, `known`/`decode_error`   |
| `Finding`     | one risk signal: `code`, `severity` in [0,1], `message`        |
| `RiskReport`  | aggregated `score`, `decision`, `findings`, `rationale`         |

Everything is JSON-serializable, so transactions and reports move cleanly
between the CLI, the eval harness, the dataset, and (later) the LLM.

## Tools

- **decoder** — pure-stdlib calldata decoding against a hardcoded selector DB
  (offline, no 4byte lookups). Covers the in-scope drainer surface: `approve`,
  `increaseAllowance`, `transferFrom`, `setApprovalForAll`, `permit`, `transfer`.
- **simulator** *(optional)* — forked `eth_call` via Anvil/RPC to detect reverts.
  Degrades to "unavailable" with no effect on the baseline.
- **rules engine** — the baseline scorer. Detects unlimited approvals, operator
  approvals, gasless permits, pull-transfers, address poisoning, unknown
  interactions, and native value sends. Findings combine with noisy-OR.
- **llm explainer** *(optional)* — provider wiring + an injection-sanitation
  step for untrusted on-chain strings. Seed of the Phase-2 agent.

## Decision policy

- `score >= 0.60` -> **BLOCK**
- `score >= 0.25` -> **WARN**
- otherwise        -> **ALLOW**
- cannot assess (unknown selector, decode failure, reverting sim) -> **ESCALATE**

## Where the three research gaps attach (see proposal, Deliverable B)

- **Injection resilience** — the `llm.sanitize()` boundary where untrusted
  on-chain data enters the agent.
- **Risk calibration / abstention** — the `score` and the ESCALATE band; Phase 2
  adds ECE / Brier / risk–coverage evaluation.
- **Dynamic investigation** — the agent loop that chooses which tools to call
  (vs. the baseline's fixed decode→rules path).
