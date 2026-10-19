"""GuardianTx: pre-signing Ethereum transaction risk analysis.

Phase-1 baseline: a deterministic, non-agentic pipeline that decodes a
transaction's calldata, inspects approvals/transfers, and assigns a
calibrated-later risk score with an ALLOW / WARN / BLOCK / ESCALATE decision.

The LLM agent and Anvil-backed simulation are optional and slot in on top of
this baseline (see docs/ARCHITECTURE.md); the baseline itself has zero runtime
dependencies.
"""

from .contracts import Transaction, DecodedCall, Finding, RiskReport, Decision
from .pipeline import analyze

__all__ = [
    "Transaction",
    "DecodedCall",
    "Finding",
    "RiskReport",
    "Decision",
    "analyze",
]

__version__ = "0.1.0"
