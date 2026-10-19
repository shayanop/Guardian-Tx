# GuardianTx

**An injection-resilient agent for risk-calibrated, pre-signing Ethereum
transaction defense.**

GuardianTx inspects an Ethereum transaction *before* a user signs it, decodes
what it actually does, and returns a risk decision — **ALLOW / WARN / BLOCK /
ESCALATE** — with a human-readable rationale. It targets the wallet-drainer
patterns behind most crypto theft: unlimited token approvals, NFT operator
approvals, gasless permits, pull-transfers, and address poisoning.

This repository is the **Phase-1 technical baseline**. It is a deterministic,
non-agentic pipeline (the baseline the proposed LLM agent is measured against).
The baseline runs on the **Python standard library alone** — no dependencies, no
API keys, no network.

> Course: AI4015 Agentic AI — Semester Project, Phase 1 (Deliverable C).
> Base paper: *Approve Once, Regret Forever: On the Exploitation of Ethereum's
> Approve-TransferFrom Ecosystem* (USENIX Security 2025).

## Quick start

```bash
# 1. (re)build the labeled seed dataset  (24 benign/malicious transactions)
python data/build_seed.py

# 2. run the baseline over the dataset and print initial results
python eval/evaluate.py

# 3. analyze a single transaction
echo '{"to":"0xA0b8...","from":"0x1111...","data":"0x095ea7b3..."}' | python -m guardiantx.cli
python -m guardiantx.cli --file tx.json --json

# 4. run the tests (no framework needed; pytest also works)
python tests/test_decoder.py && python tests/test_rules.py && python tests/test_pipeline.py
```

## Initial baseline results

On the 24-transaction seed set (positive = BLOCK/ESCALATE; WARN counts as a
soft pass, so the baseline is deliberately understated):

| Metric            | Value |
|-------------------|-------|
| Accuracy          | 0.875 |
| Precision         | 1.000 |
| Recall            | 0.750 |
| F1                | 0.857 |
| False-block rate  | 0.000 |

The three misses are the hard cases that motivate the agent: a bounded gasless
permit, a bare native-value send, and a `transferFrom` pull — all signatures the
rules see but cannot confidently convict without reputation/context lookups.

## What's here (Deliverable C checklist)

- **Finalized architecture** — [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- **Data pipeline** — [data/build_seed.py](data/build_seed.py) → `data/seed_transactions.jsonl`
- **Working baseline + results** — [eval/evaluate.py](eval/evaluate.py)
- **Tool interfaces** — decoder, simulator, rules in [guardiantx/](guardiantx/)
- **Structured contracts** — [guardiantx/contracts.py](guardiantx/contracts.py)
- **Model integration / provider setup** *(optional)* — [guardiantx/llm.py](guardiantx/llm.py)
- **End-to-end workflow** — [guardiantx/cli.py](guardiantx/cli.py)
- **Test suite** — [tests/](tests/)

## Optional components

| Capability        | Enable with                                                    |
|-------------------|----------------------------------------------------------------|
| Tx simulation     | `pip install web3`, run `anvil`, set `GUARDIANTX_RPC_URL`       |
| LLM explanation   | `pip install anthropic`, set `ANTHROPIC_API_KEY`               |

Both degrade silently when absent — the baseline results above reproduce without
either.

## Layout

```
guardiantx/      core package (contracts, decoder, signatures, simulator, rules, pipeline, llm, cli)
data/            dataset builder + generated seed set
eval/            evaluation harness (metrics, confusion matrix, per-category)
tests/           decoder / rules / pipeline tests
docs/            architecture
```

## Roadmap to the proposed system (Phase 2+)

- LLM agent that *dynamically* chooses tools to investigate a transaction
- Prompt-injection taxonomy + resilience eval over untrusted on-chain data
- Calibrated confidence (ECE, Brier, risk–coverage) and principled abstention
- Expand the corpus toward ~400 tx with held-out unseen attack types
