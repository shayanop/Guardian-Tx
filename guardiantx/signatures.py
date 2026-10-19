"""Known function-selector database for the in-scope attack surface.

Selectors are the public, well-known 4-byte keccak prefixes of each signature,
hardcoded so the baseline needs no keccak/eth-utils dependency and never calls
out to a 4byte directory (offline + privacy-preserving).

Each entry lists the ordered (name, type) params so the decoder can turn
calldata words into named args. Only static types appear here (see encoding.py).
"""
from __future__ import annotations

# name -> (signature, [(arg_name, abi_type), ...])
SIGNATURES: dict[str, dict] = {
    "0x095ea7b3": {
        "function": "approve",
        "signature": "approve(address,uint256)",
        "params": [("spender", "address"), ("amount", "uint256")],
    },
    "0xa9059cbb": {
        "function": "transfer",
        "signature": "transfer(address,uint256)",
        "params": [("to", "address"), ("amount", "uint256")],
    },
    "0x23b872dd": {
        "function": "transferFrom",
        "signature": "transferFrom(address,address,uint256)",
        "params": [("from", "address"), ("to", "address"), ("amount", "uint256")],
    },
    "0xa22cb465": {
        "function": "setApprovalForAll",
        "signature": "setApprovalForAll(address,bool)",
        "params": [("operator", "address"), ("approved", "bool")],
    },
    "0x39509351": {
        "function": "increaseAllowance",
        "signature": "increaseAllowance(address,uint256)",
        "params": [("spender", "address"), ("addedValue", "uint256")],
    },
    "0xd505accf": {
        "function": "permit",
        "signature": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
        # we only need the first three for risk; decode what we can safely
        "params": [
            ("owner", "address"),
            ("spender", "address"),
            ("value", "uint256"),
            ("deadline", "uint256"),
            ("v", "uint256"),
        ],
    },
}


def lookup(selector: str) -> dict | None:
    return SIGNATURES.get(selector.lower())
