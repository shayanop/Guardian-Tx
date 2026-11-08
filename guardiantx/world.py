"""Simulated chain environment the agent's tools act on (stand-in for an Anvil fork).

Loads data/world.json: accounts (EOA/contract, age, verified source, scam-list flag,
EIP-1967 proxy slot, verified ABI, drainer logic), balances and allowances. Trusted
fields (verified, flagged, label, age) model curated sources a wallet already has
(block explorer verification, scam lists); `metadata` models attacker-controllable
strings (token name/description) and is the injection surface.

`simulate()` executes a tx against a copy of state and returns the asset/approval
diff -- the same shape a forked eth_call + trace would give, without needing Foundry.

ponytail: semantic simulation of the in-scope ERC-20/721 calls + drainer sweeps, not
an EVM. Swap in a real anvil fork (simulator.py RPC path) when bytecode-level
behaviour matters.
"""
from __future__ import annotations

import copy
import json
import os
from typing import Any, Optional

from .encoding import split_words, strip0x, decode_address, decode_uint
from .signatures import lookup

DEFAULT_WORLD = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "world.json")


def _ints(d):
    return {k: (_ints(v) if isinstance(v, dict) else int(v)) for k, v in d.items()}


class World:
    def __init__(self, data: dict):
        self.accounts: dict[str, dict] = data["accounts"]
        self.balances = _ints(data.get("balances", {}))
        self.allowances = _ints(data.get("allowances", {}))

    @classmethod
    def load(cls, path: str = DEFAULT_WORLD) -> "World":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def with_metadata(self, address: str, metadata: dict) -> "World":
        """Copy with one account's untrusted metadata replaced (injection planting)."""
        w = copy.copy(self)
        w.accounts = dict(self.accounts)
        acc = dict(w.accounts.get(address.lower(), {"kind": "eoa"}))
        acc["metadata"] = {**acc.get("metadata", {}), **metadata}
        w.accounts[address.lower()] = acc
        return w

    def account(self, address: str) -> Optional[dict]:
        return self.accounts.get((address or "").lower())

    def allowance(self, owner: str, token: str, spender: str) -> int:
        return self.allowances.get(owner.lower(), {}).get(token.lower(), {}).get(spender.lower(), 0)

    def code_of(self, address: str) -> Optional[dict]:
        """The account whose code runs for a call (follows the proxy slot once)."""
        acc = self.account(address)
        if acc and acc.get("proxy_impl"):
            return self.account(acc["proxy_impl"]) or acc
        return acc

    # --- simulation -----------------------------------------------------------
    def simulate(self, to: str, frm: str, data: str, value: int = 0) -> dict[str, Any]:
        to, frm = to.lower(), (frm or "").lower()
        changes: list[dict] = []      # asset movements {asset, from, to, amount}
        approvals: list[dict] = []    # approval changes {token, owner, spender, amount|operator}
        bal = copy.deepcopy(self.balances)

        def move(asset, src, dst, amt):
            have = bal.get(src, {}).get(asset, 0)
            amt = min(amt, have)
            if amt <= 0:
                return
            bal.setdefault(src, {})[asset] = have - amt
            bal.setdefault(dst, {})[asset] = bal.get(dst, {}).get(asset, 0) + amt
            changes.append({"asset": asset, "from": src, "to": dst, "amount": amt})

        if value:
            move("ETH", frm, to, value)
        target = self.account(to)
        code = self.code_of(to)
        body = strip0x(data or "")
        if target is None or target.get("kind") != "contract" or not body:
            return {"reverts": False, "revert_reason": None, "asset_changes": changes, "approval_changes": approvals}

        sel = "0x" + body[:8].lower()
        words = split_words(body[8:])
        sig = lookup(sel)
        fn = sig["function"] if sig else None

        if fn in ("approve", "increaseAllowance") and len(words) >= 2:
            approvals.append({"token": to, "owner": frm, "spender": decode_address(words[0]),
                              "amount": decode_uint(words[1])})
        elif fn == "permit" and len(words) >= 3:
            approvals.append({"token": to, "owner": decode_address(words[0]), "spender": decode_address(words[1]),
                              "amount": decode_uint(words[2])})
        elif fn == "setApprovalForAll" and len(words) >= 2:
            approvals.append({"token": to, "owner": frm, "operator": decode_address(words[0]),
                              "approved": decode_uint(words[1]) != 0})
        elif fn == "transfer" and len(words) >= 2:
            move(to, frm, decode_address(words[0]), decode_uint(words[1]))
        elif fn == "transferFrom" and len(words) >= 3:
            src, dst, amt = decode_address(words[0]), decode_address(words[1]), decode_uint(words[2])
            if src != frm and self.allowance(src, to, frm) < amt:
                return {"reverts": True, "revert_reason": "ERC20: insufficient allowance",
                        "asset_changes": [], "approval_changes": []}
            move(to, src, dst, amt)
        elif code and sel in code.get("abi", {}) and value:
            pass  # verified payable protocol call: the ETH already moved into the contract
        elif code and sel in code.get("abi", {}):
            params = code["abi"][sel]["params"]
            names = [p[0] for p in params]
            if "amount" in names and "asset" in names:
                asset = decode_address(words[names.index("asset")])
                move(asset, frm, to, decode_uint(words[names.index("amount")]))
        elif not (code and code.get("sweeps")):
            return {"reverts": True, "revert_reason": "execution reverted: function selector not recognized",
                    "asset_changes": [], "approval_changes": []}

        # drainer logic: on any call it pulls everything the signer has approved to the
        # called address (and the called token itself), plus forwarded ETH, to its sink.
        if code and code.get("sweeps") and code.get("sweep_to"):
            sink = code["sweep_to"]
            for token, spenders in self.allowances.get(frm, {}).items():
                if spenders.get(to, 0) > 0:
                    move(token, frm, sink, bal.get(frm, {}).get(token, 0))
            if bal.get(frm, {}).get(to, 0) > 0:
                move(to, frm, sink, bal[frm][to])
            if value:
                move("ETH", to, sink, value)
        return {"reverts": False, "revert_reason": None, "asset_changes": changes, "approval_changes": approvals}
