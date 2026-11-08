"""E2 - the base paper's approach (Osprey, Ruaro et al., USENIX Security 2025) on our data.

Osprey is an offline, contract-side analyser: it finds contracts exposing the
Approved-Controllable-TransferFrom (ACT) pattern. The closest pre-signing use of
that capability is: BLOCK a transaction if any contract it touches or empowers
(target, the target's proxy implementation, the approved spender/operator) is
ACT-flagged; otherwise ALLOW.

We cannot run Osprey itself (symbolic execution over bytecode; our world has no
bytecode). Instead we give this baseline ORACLE access to the ground-truth `act`
attribute of every contract, i.e. a perfect Osprey. Its numbers are therefore an
UPPER BOUND on what contract-side ACT detection contributes before signing, and
are reported as "re-implemented (oracle)", not as numbers from the paper.
"""
from __future__ import annotations

from .assess import counterparties
from .contracts import Decision
from .decoder import decode
from .world import World


def osprey_oracle(tx, world: World) -> tuple[Decision, list[str]]:
    d = decode(tx)
    dec = {"known": d.known, "function": d.function, "args": d.args}
    touched = {tx.to.lower(), *counterparties(tx, dec).values()}
    acc = world.account(tx.to)
    if acc and acc.get("proxy_impl"):
        touched.add(acc["proxy_impl"])
    hits = [a for a in touched if (world.account(a) or {}).get("act")]
    return (Decision.BLOCK if hits else Decision.ALLOW), hits
