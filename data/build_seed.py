"""Deterministically build the Phase-1 seed evaluation set.

Generates valid calldata for each labeled scenario using the package's own
encoders, so the dataset is reproducible and the calldata is guaranteed correct.
Run from the repo root:  python data/build_seed.py

This is the seed (~24 tx) for the working baseline. Phase 2 expands it toward
the ~400 benign/malicious corpus described in the proposal, with unseen attack
types held out for final evaluation.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardiantx.encoding import (  # noqa: E402
    MAX_UINT256, build_calldata, enc_address, enc_bool, enc_uint,
)

# selectors
APPROVE = "095ea7b3"
TRANSFER = "a9059cbb"
TRANSFER_FROM = "23b872dd"
SET_APPROVAL_FOR_ALL = "a22cb465"
INCREASE_ALLOWANCE = "39509351"
PERMIT = "d505accf"

# actors
VICTIM = "0x1111111111111111111111111111111111111111"
ROUTER = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"  # known DEX router (benign spender)
FRIEND = "0x2222222222222222222222222222222222222222"
DRAINER = "0xbaD0000000000000000000000000000000DeAd01"
USDC = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"      # known counterparty
# address-poisoning look-alike: same first4 (a0b8) + last4 (eb48), different middle
POISON = "0xa0b800000000000000000000000000000000eb48"

SMALL = 1_000_000           # 1 USDC (6 decimals)
BIG_BOUNDED = 1 << 128      # large but bounded


def approve(spender, amount):
    return build_calldata("0x" + APPROVE, enc_address(spender), enc_uint(amount))


def transfer(to, amount):
    return build_calldata("0x" + TRANSFER, enc_address(to), enc_uint(amount))


def transfer_from(frm, to, amount):
    return build_calldata("0x" + TRANSFER_FROM, enc_address(frm), enc_address(to), enc_uint(amount))


def set_approval_for_all(op, approved):
    return build_calldata("0x" + SET_APPROVAL_FOR_ALL, enc_address(op), enc_bool(approved))


def increase_allowance(spender, added):
    return build_calldata("0x" + INCREASE_ALLOWANCE, enc_address(spender), enc_uint(added))


def permit(owner, spender, value):
    return build_calldata(
        "0x" + PERMIT, enc_address(owner), enc_address(spender), enc_uint(value),
        enc_uint(9999999999), enc_uint(27),  # deadline, v (r,s omitted; decoder reads what it needs)
    )


ROWS = [
    # ---------------- malicious ----------------
    dict(id="m01", label="malicious", category="approval_phishing",
         to=USDC, **{"from": VICTIM}, data=approve(DRAINER, MAX_UINT256),
         note="unlimited USDC approval to an unknown drainer"),
    dict(id="m02", label="malicious", category="approval_phishing",
         to=USDC, **{"from": VICTIM}, data=increase_allowance(DRAINER, MAX_UINT256),
         note="increaseAllowance to unlimited for a drainer"),
    dict(id="m03", label="malicious", category="nft_operator",
         to="0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", **{"from": VICTIM},
         data=set_approval_for_all(DRAINER, True),
         note="setApprovalForAll(true) handing a whole NFT collection to an operator"),
    dict(id="m04", label="malicious", category="gasless_permit",
         to=USDC, **{"from": VICTIM}, data=permit(VICTIM, DRAINER, MAX_UINT256),
         note="unlimited gasless permit to a drainer"),
    dict(id="m05", label="malicious", category="address_poisoning",
         to=USDC, **{"from": VICTIM}, data=transfer(POISON, SMALL),
         recent_counterparties=[USDC],
         note="transfer to an address that mimics a known counterparty"),
    dict(id="m06", label="malicious", category="pull_transfer",
         to=USDC, **{"from": DRAINER}, data=transfer_from(VICTIM, DRAINER, BIG_BOUNDED),
         note="transferFrom pulling the victim's tokens to the attacker"),
    dict(id="m07", label="malicious", category="suspicious_proxy",
         to=DRAINER, **{"from": VICTIM}, data="0xdeadbeef" + "00" * 32, value=0,
         note="call to an unknown selector on an unverified contract"),
    dict(id="m08", label="malicious", category="gasless_permit",
         to=USDC, **{"from": VICTIM}, data=permit(VICTIM, DRAINER, SMALL),
         note="bounded permit to a drainer (harder case: looks small)"),
    dict(id="m09", label="malicious", category="approval_phishing",
         to=USDC, **{"from": VICTIM}, data=approve(DRAINER, 1 << 255),
         note="2**255 'effectively infinite' approval to a drainer"),
    dict(id="m10", label="malicious", category="nft_operator",
         to="0x60E4d786628Fea6478F785A6d7e704777c86a7c6", **{"from": VICTIM},
         data=set_approval_for_all(DRAINER, True),
         note="operator approval on a second NFT collection"),
    dict(id="m11", label="malicious", category="address_poisoning",
         to=USDC, **{"from": VICTIM}, data=transfer(POISON, BIG_BOUNDED),
         recent_counterparties=[USDC, ROUTER],
         note="larger poisoned transfer to a look-alike address"),
    dict(id="m12", label="malicious", category="suspicious_proxy",
         to=DRAINER, **{"from": VICTIM}, data="0x", value=5 * 10**18,
         note="5 ETH native transfer to an unknown address with no calldata"),

    # ---------------- benign ----------------
    dict(id="b01", label="benign", category="dex_approval",
         to=USDC, **{"from": VICTIM}, data=approve(ROUTER, BIG_BOUNDED),
         note="bounded approval to a known DEX router for a swap"),
    dict(id="b02", label="benign", category="token_transfer",
         to=USDC, **{"from": VICTIM}, data=transfer(FRIEND, SMALL),
         note="small token transfer to a normal address"),
    dict(id="b03", label="benign", category="revoke",
         to="0xBC4CA0EdA7647A8aB7C2061c2E118A18a936f13D", **{"from": VICTIM},
         data=set_approval_for_all(ROUTER, False),
         note="revoking operator approval (safe)"),
    dict(id="b04", label="benign", category="revoke",
         to=USDC, **{"from": VICTIM}, data=approve(ROUTER, 0),
         note="setting allowance back to zero (revoke)"),
    dict(id="b05", label="benign", category="dex_approval",
         to=USDC, **{"from": VICTIM}, data=increase_allowance(ROUTER, SMALL),
         note="small increaseAllowance to a known router"),
    dict(id="b06", label="benign", category="self_transfer_from",
         to=USDC, **{"from": VICTIM}, data=transfer_from(VICTIM, FRIEND, SMALL),
         note="transferFrom where the signer is the source (legit)"),
    dict(id="b07", label="benign", category="native_transfer",
         to=FRIEND, **{"from": VICTIM}, data="0x", value=10**16,
         note="0.01 ETH to a known friend, no calldata"),
    dict(id="b08", label="benign", category="token_transfer",
         to=USDC, **{"from": VICTIM}, data=transfer(FRIEND, BIG_BOUNDED),
         recent_counterparties=[FRIEND],
         note="larger transfer to a genuine recent counterparty (not poisoned)"),
    dict(id="b09", label="benign", category="dex_approval",
         to=USDC, **{"from": VICTIM}, data=approve(ROUTER, SMALL),
         note="exact-amount approval to a known router"),
    dict(id="b10", label="benign", category="token_transfer",
         to=USDC, **{"from": VICTIM}, data=transfer(FRIEND, 42),
         note="dust transfer to a normal address"),
    dict(id="b11", label="benign", category="native_transfer",
         to=FRIEND, **{"from": VICTIM}, data="0x", value=10**15,
         note="0.001 ETH tip to a friend"),
    dict(id="b12", label="benign", category="revoke",
         to="0x60E4d786628Fea6478F785A6d7e704777c86a7c6", **{"from": VICTIM},
         data=set_approval_for_all(ROUTER, False),
         note="revoke operator approval on a collection"),
]


def main():
    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "seed_transactions.jsonl")
    with open(out, "w", encoding="utf-8") as f:
        for row in ROWS:
            f.write(json.dumps(row) + "\n")
    print(f"wrote {len(ROWS)} transactions -> {out}")


if __name__ == "__main__":
    main()
