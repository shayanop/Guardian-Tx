"""Minimal ABI word helpers for the fixed-layout calls we care about.

The whole wallet-drainer taxonomy in scope (approve, transferFrom,
setApprovalForAll, permit, increaseAllowance, transfer) uses only *static*
head-encoded params: address, uint*, bool. Those are one 32-byte word each, so
we decode them with the stdlib and skip the eth-abi dependency entirely.

ponytail: static types only. If a scoped selector ever needs dynamic types
(bytes/arrays), add eth-abi rather than growing this by hand.
"""
from __future__ import annotations

MAX_UINT256 = (1 << 256) - 1
WORD = 64  # hex chars per 32-byte word


def strip0x(h: str) -> str:
    return h[2:] if h.startswith(("0x", "0X")) else h


def split_words(params_hex: str) -> list[str]:
    """Split the calldata body (after the 4-byte selector) into 32-byte words."""
    p = strip0x(params_hex)
    return [p[i:i + WORD] for i in range(0, len(p), WORD)]


def decode_address(word: str) -> str:
    return "0x" + word[-40:]


def decode_uint(word: str) -> int:
    return int(word, 16) if word else 0


def decode_bool(word: str) -> bool:
    return int(word, 16) != 0 if word else False


# --- encoders (used by the dataset builder and tests to produce valid calldata) ---

def enc_address(addr: str) -> str:
    return strip0x(addr).lower().rjust(WORD, "0")


def enc_uint(n: int) -> str:
    return format(n, "x").rjust(WORD, "0")


def enc_bool(b: bool) -> str:
    return enc_uint(1 if b else 0)


def build_calldata(selector: str, *words: str) -> str:
    return selector + "".join(words)
