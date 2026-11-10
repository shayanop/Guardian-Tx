# Development log (Phase 2)

Each entry: date, observed failure or limitation, change, measured effect.
All numbers come from `python experiments/run.py all` and files under `results/`.
Unless stated otherwise, they are TEST-split numbers (261 tx; 45 from held-out attack types).

---

## Iteration 0 — 2026-11-02 — Phase-1 baseline on the Phase-2 corpus

- **Observed:** On the 24-tx seed set the rules baseline scored F1 0.857. On the new
  405-tx corpus it scores **F1 0.545** on test (95% CI 0.463–0.617), with a
  **false-block rate of 25.8%**. The false blocks are the benign patterns that look
  like drainer steps: unlimited approvals to verified routers, NFT operator approvals
  to marketplaces, permits to Permit2, and verified protocol calls whose selectors the
  base DB does not know. On the held-out attack types it gets F1 0.500, because a
  proxy-upgrade drain and a look-alike spender both use ordinary `transfer`/`approve`
  calls.
- **Change:** none. This is the E1 reference point, and it motivates the context tools
  (G3) and the calibrated decision bands (G2).

## Iteration 1 — 2026-11-02 — first complete agent

- **Built:** a simulated chain environment (`world.py`) and five tools with retries
  (`tools.py`). An evidence assessor (`assess.py`), a deterministic data-dependent
  planner and a fixed-order ablation planner (`agent.py`). Platt calibration with
  thresholds fit on dev (`calibration.py`). A regex sanitizer plus a decision-floor
  verifier (`guard.py`).
- **Bug found while wiring E4:** the worst-case reasoner looked for the payload inside
  `json.dumps(observation)`. JSON escaping of quotes and newlines hid the
  tool-output-laundering payloads, so their attacks were never "seen". Fixed by matching
  against the raw string values.
- **Measured:** F1 0.975, precision 1.000, recall 0.950, false-block rate 0.0%.
- **Limitations observed** (protocol note: seen on the TEST split in this first full
  run, before any dev analysis was done):
  1. *G2:* calibrated ECE 0.091 was **worse** than uncalibrated 0.081. The dev
     F1-maximising rule put `t_low == t_block = 0.563`, so the abstention band was
     empty.
  2. *G1:* the sanitizer caught 100% of dev payloads but only **20% of test payloads**.
     The test templates use disjoint phrasings, so the regexes are overfit to dev
     wording. With the full guard, the worst-case attack success rate was still
     **24.3%**, coming entirely from the "rationale" goal: attacker text copied into
     the user-facing explanation, which the decision floor does not cover.
  3. *G3:* the fixed-order planner matched the dynamic planner's F1 on the held-out
     types (both 1.000). On held-out cases, dynamic selection reduced neither errors
     nor tool calls.

## Iteration 2 — 2026-11-02 — G2: select the calibration method on dev, budget the review band

- **Analysis (dev only):** 5-fold CV within the dev split. For the agent's raw score,
  Platt was worse than the identity map (CV ECE 0.070 vs 0.058; Brier 0.0567 vs
  0.0547). The noisy-OR over tool evidence is already close to calibrated. For the
  Phase-1 rules score, Platt helps a lot (CV ECE 0.238 → 0.062).
- **Change:** `Calibrator.fit` keeps Platt only when it beats the identity map on dev CV
  Brier. `t_low` is now set from a human-review budget: the lowest threshold that sends
  ≤10% of dev benign tx to ESCALATE. It is no longer an F1 maximiser that collapses the
  band.
- **Effect (test):** the agent keeps the identity map, so ECE is unchanged at 0.081.
  With the abstention band, recall goes **0.950 → 0.993**, selective accuracy
  **0.973 → 0.996** at 94.3% coverage, and the false-block rate stays 0.0%. The price is
  precision 1.000 → 0.940: 7.5% of benign tx are escalated to a human. The same
  component lowers the Phase-1 scorer's test ECE from **0.344 → 0.103**.

## Iteration 3 — 2026-11-02 — G1: output provenance check

- **Analysis:** limitation 2 comes from the output channel, which the decision floor
  does not cover. More regexes would not fix it: they would only overfit further, and
  writing them from the test templates would contaminate the test set. No patterns were
  added.
- **Change:** the verifier now withholds any reasoner rationale that shares a ≥24-char
  verbatim span with untrusted text seen during the run (`guard.echoes_untrusted`).
  Like the floor, this check does not depend on phrasing.
- **Effect (test, worst-case compliant reasoner):** attack success rate with the full
  guard goes **24.3% → 0.0%**. With the verifier only it is 0.0%; with the sanitizer
  only, 72.0%; with no defense, 90.7%. Clean-data F1 is unchanged (+0.0 points).
  - *Caveat:* the decision floor makes "downgrade" attacks fail by construction. This
    result shows the architecture bounds a fully hijacked reasoner. It is not a measure
    of any real LLM's susceptibility (that needs `--planner llm`).

## Iteration 4 — 2026-11-02 — calibration threshold bug (found by unit test)

- **Observed:** `test_calibrator_thresholds_and_metrics` failed. Candidate thresholds
  were rounded to 6 decimals, so `t_block` could round *above* the highest score it was
  derived from, and nothing would ever reach BLOCK.
- **Change:** use the exact score values as candidates.
- **Effect:** no change to corpus results, because the agent uses the identity map. A
  Platt-mapped scorer is now correct.

## Iteration 5 — 2026-11-02 — LLM planner on Groq: first live runs

- **Observed, in order, on `examples/heldout_proxy_drain.json`:**
  1. Groq's Cloudflare front rejected every request (HTTP 403, error 1010) because of
     urllib's default User-Agent.
  2. The configured `llama-3.3-70b-versatile` is not available on the account. The
     `/models` listing offers `openai/gpt-oss-120b`.
  3. Free-tier rate limits (HTTP 429) ended runs after 3 calls.
  4. gpt-oss sometimes emits a malformed tool call, which Groq rejects with 400
     `tool_use_failed`.
  5. The model often ended with a prose answer instead of calling `finish`, so its own
     decision was lost (`proposed: null`).
  6. A planner that failed before decoding produced **BLOCK**, from a fake
     `DECODE_ERROR` with severity 0.5 above `t_block` 0.475. It should have been
     ESCALATE.
- **Changes:**
  - An explicit User-Agent.
  - Groq default model set to `openai/gpt-oss-120b`.
  - Retries honour `Retry-After`; `tool_use_failed` is retried.
  - One nudge to call `finish` after a prose answer.
  - The model's separate `reasoning` field is logged as the step thought.
  - `llm_errors` is counted in usage.
  - An uninvestigated tx now yields `NOT_INVESTIGATED` → ESCALATE.
  - `--sample N` evaluates a seeded stratified subset for rate-limited LLM runs.
- **Effect:** both example tx complete. The LLM chooses the decode → lookup → proxy →
  simulate path itself, proposes BLOCK through `finish`, and the verifier agrees.
  Cost is 3–5 LLM calls and about 17–31 s per tx on the free tier. Offline results
  are unchanged.

---

## Iteration 6 — 2026-11-08 — LLM-planner experiments completed (Cerebras)

- **Ran:** `experiments/run.py e3 --planner llm --runs 3 --sample 12` on Cerebras
  `gpt-oss-120b` (provider order `nim,cerebras,groq`; NIM unused, Cerebras served).
  Small seeded stratified sample (n=12) because of free-tier per-minute/per-hour caps.
- **Result (test, mean±std over 3 runs):** F1 **0.838 ± 0.033**, recall **1.000 ± 0.000**,
  precision **0.722 ± 0.048**, ECE **0.091 ± 0.021**, tool calls 4.25 ± 0.33. No hard
  failures across the 3 runs. Written to `results/e3_proposed_llm.json`.
- **Effect:** satisfies the brief's ≥3-run requirement for the LLM planner. The
  deterministic `PolicyPlanner` remains the system of record (full 261-tx test, F1 0.966);
  the LLM row is a secondary comparison with a stated small-sample (n=12) caveat.
  *Superseded by Iteration 8 (n=45).*

## Iteration 7 — 2026-11-10 — Pre-submission audit (no scoring change)

- **Checked:** all four test files pass; `experiments/run.py all` reproduces every
  metric in `results/` exactly (only wall-clock latency fields differ between runs).
- **Found:** the README and paper quoted E6 decision agreement at a 30% fault rate as
  96.6% (README also 63.7% without retries). `results/e6_efficiency_policy.json` says
  **95.7%** with retries and **53.5%** without. This was a transcription error.
- **Found:** paper prose claimed tool failures bias the no-retry agent toward unsafe
  allows, and that dynamic selection saves tool calls on held-out families. The data
  says otherwise: failures raise ESCALATE (47.5% at a 30% fault rate without retries),
  and on held-out families dynamic and fixed order use 4.71 vs 4.67 calls.
- **Change:** corrected the README line and the paper text; added the E6 reliability
  table and the per-category injection table to the paper; redrew Fig. 1.
- **Effect:** no code or result changed. Text now matches `results/`.

## Iteration 8 — 2026-11-10 — LLM planner on a larger sample (n=45), rate-limit handling

- **Motivation:** the n=12 LLM sample (Iteration 6) had one held-out tx and wide
  intervals. Free-tier caps (Cerebras ~5 RPM plus an hourly cap; Groq 200k tokens/day)
  made a larger run impossible with one provider.
- **Change (`llm.py`, `experiments/run.py`):** calls rotate between providers serving the
  same model (Cerebras and Groq, `gpt-oss-120b`), and a rate-limited provider is skipped
  until its cooldown ends. `--resume` checkpoints each successful tx
  (`logs/llm_checkpoint.pkl`, ignored by git), so an interrupted run continues instead of
  restarting. `GUARDIANTX_MAX_WAIT` lets an unattended run sleep through an hourly quota
  reset. NIM is excluded because it serves a different model.
- **Failures on the way:** the first 3×45 run lost 8 tx to a local DNS outage
  (`getaddrinfo failed`). It lost 30 more when both quotas ran out at once (Cerebras
  hourly, Groq 198.5k/200k tokens), and those failed instantly with a misleading
  "no LLM provider configured" error. Those results were discarded, not reported:
  fail-safe ESCALATEs would have distorted precision and ECE. Fixed the error message,
  added the quota wait and a test for each, then resumed. The 97 good tx came from the
  checkpoint and the 38 failed ones were re-run.
- **Result (test sample, 3 runs, 0/135 tx with LLM errors; 477 Cerebras + 226 Groq
  calls):** F1 **0.893 ± 0.000**, precision **0.806 ± 0.000**, recall **1.000**,
  false-block **0.000**, ECE **0.127 ± 0.022**, 4.01 ± 0.23 tool calls. Held-out slice
  (n=9) F1 1.000. Identical confusion counts in every run (25 TP / 6 FP / 14 TN / 0 FN).
  The 6 false flags are WARN/ESCALATE across nine benign categories (20% escalation).
- **Like-for-like reference:** E3 now also scores the PolicyPlanner on the same sample
  (`policy_same_sample`): F1 0.980, precision 0.962, ECE 0.076, 4.4% escalation. The
  n=12 false-block mean of 0.056 (one benign block in one run) did not recur at n=45.
- **Effect:** the paper, README and this log now report n=45. The PolicyPlanner remains
  the system of record. The LLM planner is safe here (no misses, no false blocks) but
  over-cautious.

---

## Open items
- 7 of 10 test failures are benign approvals to new/unverified dapps that get escalated
  (`new_dapp_bounded`). Reputation tools alone cannot tell a new legitimate dapp from new
  attacker infrastructure. A candidate fix is a verified-source / audit-registry tool.
