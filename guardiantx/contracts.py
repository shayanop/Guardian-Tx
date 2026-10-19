"""Structured contracts: the state/context objects that flow through the pipeline.

These dataclasses are the stable interface between tools (decoder, simulator,
rules) and the orchestrator. Everything is JSON-serializable so transactions,
findings, and reports can be logged, stored in the eval set, or handed to an
LLM later.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional


class Decision(str, Enum):
    ALLOW = "ALLOW"        # low risk, safe to sign
    WARN = "WARN"          # proceed with caution, surface findings to user
    BLOCK = "BLOCK"        # high risk, recommend not signing
    ESCALATE = "ESCALATE"  # cannot assess confidently -> human review


@dataclass
class Transaction:
    """A pre-signing Ethereum transaction request (EIP-1559 style, minimal)."""
    to: str                      # target contract / recipient, 0x-address
    data: str = "0x"             # calldata hex
    value: int = 0               # wei
    frm: Optional[str] = None    # sender (the wallet about to sign); `from` is reserved
    chain_id: int = 1
    # Optional context a wallet can supply to sharpen heuristics (none required):
    recent_counterparties: list[str] = field(default_factory=list)
    known_tokens: dict[str, str] = field(default_factory=dict)  # addr -> symbol

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DecodedCall:
    selector: str                      # 0x + 8 hex
    function: Optional[str]            # e.g. "approve" or None if unknown
    signature: Optional[str]          # e.g. "approve(address,uint256)"
    args: dict[str, Any] = field(default_factory=dict)
    known: bool = False                # selector present in the signature DB
    decode_error: Optional[str] = None


@dataclass
class Finding:
    code: str          # stable machine code, e.g. "UNLIMITED_APPROVAL"
    severity: float    # risk contribution in [0, 1]
    message: str       # human-readable
    source: str = "rules"  # which tool raised it

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RiskReport:
    tx: Transaction
    decoded: DecodedCall
    findings: list[Finding]
    score: float          # aggregated risk in [0, 1]
    decision: Decision
    rationale: str
    explanation: Optional[str] = None  # optional LLM narrative (agent layer)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["decision"] = self.decision.value
        return d
