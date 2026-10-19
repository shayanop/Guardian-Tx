"""End-to-end orchestration: Transaction -> RiskReport.

This is the single public entry point tying the tools together:
    decode -> (optional simulate) -> rules -> (optional LLM explanation)

The baseline path (decode + rules) runs with zero dependencies. Simulation and
the LLM narrative are additive and skipped silently when unavailable.
"""
from __future__ import annotations

from .contracts import RiskReport, Transaction
from .decoder import decode
from .rules import evaluate


def analyze(tx: Transaction, *, simulate: bool = False, explain: bool = False) -> RiskReport:
    decoded = decode(tx)

    sim = None
    if simulate:
        from .simulator import simulate as run_sim
        sim = run_sim(tx)

    report = evaluate(tx, decoded, sim)

    if explain:
        from .llm import explain as run_explain
        report.explanation = run_explain(report)

    return report


def analyze_dict(d: dict, **kw) -> RiskReport:
    """Build a Transaction from a plain dict (dataset rows / JSON input)."""
    tx = Transaction(
        to=d["to"],
        data=d.get("data", "0x"),
        value=int(d.get("value", 0)),
        frm=d.get("from") or d.get("frm"),
        chain_id=int(d.get("chain_id", 1)),
        recent_counterparties=d.get("recent_counterparties", []),
        known_tokens=d.get("known_tokens", {}),
    )
    return analyze(tx, **kw)
