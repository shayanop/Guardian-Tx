# GuardianTx — Architecture (Phase 2)

GuardianTx analyzes an Ethereum transaction **before the user signs it** and
returns `ALLOW` / `WARN` / `BLOCK` / `ESCALATE`. Phase 1 shipped a fixed
decode → rules baseline (`pipeline.analyze`, still available and used as E1).
Phase 2 adds an investigating agent built on the same contracts.

## Control flow (`agent.run_agent`)

```
Transaction ──► State(tx, Toolbox, Evidence)
                 │
                 ▼
     ┌──► planner.next(state) ──► Action(thought, tool, args)  ─┐
     │        (policy | fixed | llm | compliant wrapper)        │ finish?
     │                                                          ▼
     │   Toolbox.call(tool, args)  (retries, fault injection, sanitizer on untrusted text)
     │        │ observation
     └────────┴── Evidence.record(...); trace.steps.append(...)
                 │ (finish or step budget)
                 ▼
  assess(tx, evidence) → findings, raw score, cannot_assess, missing evidence
  Calibrator.decide(raw) → probability, evidence decision            (G2)
  guard.verify(evidence decision, proposed, missing) → final         (G1)
  guard.echoes_untrusted(rationale) → withhold copied attacker text  (G1)
                 ▼
  RiskReport + trace {steps, final, usage}
```

## Components

| Module | Role |
|---|---|
| `world.py` | Simulated chain: accounts (EOA/contract, age, verified, scam-listed, proxy slot, verified ABI, drainer logic), balances, allowances, untrusted metadata. `simulate()` returns asset and approval diffs. |
| `tools.py` | `decode_calldata` (optionally with a verified ABI), `lookup_address`, `resolve_proxy`, `simulate_tx`, `inspect_allowance`. Retries; untrusted strings pass through the sanitizer; JSON specs for the LLM. |
| `assess.py` | Phase-1 rule findings on the (re-)decoded call, discounted or boosted by tool evidence; required-evidence checklist. Uses only trusted fields. |
| `calibration.py` (G2) | Platt scaling kept only if it wins on dev CV; `t_block` from a false-block budget; `t_low` from a human-review budget; the band between them is ESCALATE. |
| `guard.py` (G1) | `screen` (normalise, decode, match the injection taxonomy, quarantine); `verify` (decision floor + evidence checklist); `echoes_untrusted` (output provenance). |
| `agent.py` (G3) | Loop, `PolicyPlanner` (data-dependent), `FixedPlanner` (ablation), `CompliantPlanner` (worst-case G1 reasoner). |
| `llm.py` | `LLMPlanner`: OpenAI-compatible function-calling loop (NVIDIA NIM, falling back to Groq), tool results answered per call id, `finish` tool. Its proposal goes through the same verifier. |
| `baselines.py` | Oracle re-implementation of Osprey's ACT detection for E2. |

## Trust boundary

Trusted: code facts and curated registries (verification status, scam lists,
age, proxy slots, verified ABIs, simulation diffs). Untrusted: contract-supplied
metadata strings and revert reasons. Untrusted text never contributes to the
score except as the `INJECTION_ATTEMPT` signal, and it never reaches the user
verbatim through the reasoner's rationale.

## Decision policy

`p = calibrator.prob(raw)`:
- `p ≥ t_block` → **BLOCK**
- cannot assess (undecodable or unknown selector with no simulation) → **ESCALATE**
- `t_low ≤ p < t_block` → **ESCALATE** (abstention band)
- otherwise **WARN** if any finding has severity ≥ 0.25, else **ALLOW**

The verifier then raises the decision to the reasoner's proposal if that is
stricter (it never lowers it). It also ESCALATEs when required evidence is
missing, for example the spender was never looked up or an unknown selector was
never simulated.

Fitted values are in `results/calibration.json`, and the CLI loads them.
