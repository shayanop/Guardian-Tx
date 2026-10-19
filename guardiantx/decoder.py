"""Calldata decoder tool: raw tx -> DecodedCall.

Pure stdlib. Splits the selector, looks it up in the signature DB, and decodes
each static param word into a named arg. Unknown selectors and malformed
calldata are reported, not raised -- the risk layer treats "can't decode" as a
signal (ESCALATE), which is the whole point of pre-signing defense.
"""
from __future__ import annotations

from . import encoding as enc
from .contracts import DecodedCall, Transaction
from .signatures import lookup

_DECODERS = {
    "address": enc.decode_address,
    "uint256": enc.decode_uint,
    "bool": enc.decode_bool,
}


def decode(tx: Transaction) -> DecodedCall:
    data = enc.strip0x(tx.data or "")
    if not data:
        return DecodedCall(selector="0x", function=None, signature=None, known=False)

    if len(data) < 8:
        return DecodedCall(
            selector="0x" + data, function=None, signature=None, known=False,
            decode_error="calldata shorter than a 4-byte selector",
        )

    selector = "0x" + data[:8].lower()
    sig = lookup(selector)
    if sig is None:
        return DecodedCall(selector=selector, function=None, signature=None, known=False)

    words = enc.split_words(data[8:])
    args: dict = {}
    error = None
    for i, (name, typ) in enumerate(sig["params"]):
        if i >= len(words):
            error = f"missing word for param '{name}'"
            break
        try:
            args[name] = _DECODERS[typ](words[i])
        except Exception as e:  # malformed word
            error = f"failed to decode '{name}': {e}"
            break

    return DecodedCall(
        selector=selector,
        function=sig["function"],
        signature=sig["signature"],
        args=args,
        known=True,
        decode_error=error,
    )
