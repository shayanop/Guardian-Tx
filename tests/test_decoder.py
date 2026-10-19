"""Decoder tests. Run standalone (`python tests/test_decoder.py`) or via pytest."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardiantx.contracts import Transaction
from guardiantx.decoder import decode
from guardiantx.encoding import MAX_UINT256, build_calldata, enc_address, enc_bool, enc_uint

SPENDER = "0xbaD0000000000000000000000000000000DeAd01"


def test_decode_unlimited_approve():
    data = build_calldata("0x095ea7b3", enc_address(SPENDER), enc_uint(MAX_UINT256))
    d = decode(Transaction(to="0xabc", data=data))
    assert d.known and d.function == "approve"
    assert d.args["spender"].lower() == SPENDER.lower()
    assert d.args["amount"] == MAX_UINT256
    assert d.decode_error is None


def test_decode_set_approval_for_all():
    data = build_calldata("0xa22cb465", enc_address(SPENDER), enc_bool(True))
    d = decode(Transaction(to="0xabc", data=data))
    assert d.function == "setApprovalForAll"
    assert d.args["approved"] is True


def test_unknown_selector():
    d = decode(Transaction(to="0xabc", data="0xdeadbeef"))
    assert not d.known and d.function is None


def test_empty_calldata():
    d = decode(Transaction(to="0xabc", data="0x"))
    assert not d.known and d.selector == "0x"


def test_truncated_calldata_reports_error():
    # valid selector but missing the second param word
    d = decode(Transaction(to="0xabc", data="0x095ea7b3" + enc_address(SPENDER)))
    assert d.known and d.decode_error is not None


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all decoder tests passed")
