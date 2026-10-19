"""Optional Anvil-backed transaction simulation tool.

If Foundry's `anvil` (or any JSON-RPC endpoint via GUARDIANTX_RPC_URL) and the
`web3` package are available, this does a forked `eth_call` to see whether the
transaction reverts and what it touches. If not, it returns
`SimulationResult(available=False)` and the baseline falls back to static
analysis -- the rules layer never depends on simulation being present.

ponytail: eth_call reachability check only; full state-diff / trace decoding is
a Phase-2 upgrade. Wire real tracing here when the proposed agent needs it.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from .contracts import Transaction


@dataclass
class SimulationResult:
    available: bool
    reverts: Optional[bool] = None
    revert_reason: Optional[str] = None
    note: str = ""


def _get_web3():
    try:
        from web3 import Web3  # type: ignore
    except Exception:
        return None
    rpc = os.environ.get("GUARDIANTX_RPC_URL")
    if not rpc:
        return None
    try:
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 5}))
        return w3 if w3.is_connected() else None
    except Exception:
        return None


def simulate(tx: Transaction) -> SimulationResult:
    w3 = _get_web3()
    if w3 is None:
        return SimulationResult(
            available=False,
            note="no RPC/web3 (set GUARDIANTX_RPC_URL + run anvil for simulation)",
        )
    try:
        call = {"to": tx.to, "data": tx.data, "value": tx.value}
        if tx.frm:
            call["from"] = tx.frm
        w3.eth.call(call)
        return SimulationResult(available=True, reverts=False)
    except Exception as e:
        return SimulationResult(available=True, reverts=True, revert_reason=str(e))
