"""Risk-scoring tests for the non-agentic baseline."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardiantx.contracts import Decision, Transaction
from guardiantx.encoding import MAX_UINT256, build_calldata, enc_address, enc_bool, enc_uint
from guardiantx.pipeline import analyze

DRAINER = "0xbaD0000000000000000000000000000000DeAd01"
ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
POISON = "0xa0b800000000000000000000000000000000eb48"


def _approve(spender, amount):
    return build_calldata("0x095ea7b3", enc_address(spender), enc_uint(amount))


def test_unlimited_approval_blocks():
    r = analyze(Transaction(to=USDC, data=_approve(DRAINER, MAX_UINT256)))
    assert r.decision == Decision.BLOCK
    assert any(f.code == "UNLIMITED_APPROVAL" for f in r.findings)


def test_bounded_approval_allows():
    r = analyze(Transaction(to=USDC, data=_approve(ROUTER, 1_000_000)))
    assert r.decision == Decision.ALLOW


def test_set_approval_for_all_blocks():
    data = build_calldata("0xa22cb465", enc_address(DRAINER), enc_bool(True))
    r = analyze(Transaction(to=USDC, data=data))
    assert r.decision == Decision.BLOCK
    assert any(f.code == "OPERATOR_APPROVAL" for f in r.findings)


def test_revoke_operator_allows():
    data = build_calldata("0xa22cb465", enc_address(ROUTER), enc_bool(False))
    r = analyze(Transaction(to=USDC, data=data))
    assert r.decision == Decision.ALLOW


def test_address_poisoning_flagged():
    data = build_calldata("0xa9059cbb", enc_address(POISON), enc_uint(1000))
    r = analyze(Transaction(to=USDC, data=data, recent_counterparties=[USDC]))
    assert any(f.code == "ADDRESS_POISONING" for f in r.findings)
    assert r.decision in (Decision.BLOCK, Decision.WARN)


def test_unknown_selector_escalates():
    r = analyze(Transaction(to=DRAINER, data="0xdeadbeef"))
    assert r.decision == Decision.ESCALATE


def test_score_in_range():
    r = analyze(Transaction(to=USDC, data=_approve(DRAINER, MAX_UINT256)))
    assert 0.0 <= r.score <= 1.0


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all rules tests passed")
