"""Non-agentic baseline risk scorer.

Deterministic heuristics over the decoded call (plus optional context and
simulation). This IS the Phase-1 baseline the proposed LLM agent is measured
against. Each heuristic emits a Finding with a severity in [0,1]; findings
combine with noisy-OR so independent signals compound without ever exceeding 1.

Decision bands map score -> ALLOW / WARN / BLOCK. ESCALATE is separate: it fires
when we genuinely cannot assess the call (unknown selector, decode failure, or a
reverting simulation), which is when a human should look rather than a number.
"""
from __future__ import annotations

from .contracts import DecodedCall, Decision, Finding, RiskReport, Transaction
from .encoding import MAX_UINT256, strip0x
from .simulator import SimulationResult

# unlimited-ish: within a factor of the uint256 ceiling, covers MAX and the
# common `MAX/2` and `2**255` "effectively infinite" approval amounts.
_UNLIMITED_THRESHOLD = 1 << 200

WARN_AT = 0.25
BLOCK_AT = 0.60


def _noisy_or(severities: list[float]) -> float:
    prod = 1.0
    for s in severities:
        prod *= (1.0 - max(0.0, min(1.0, s)))
    return 1.0 - prod


def _looks_poisoned(target: str, known: list[str]) -> str | None:
    """Address-poisoning heuristic: same 4-char prefix+suffix as a known
    counterparty but a different full address (attacker vanity look-alike)."""
    t = strip0x(target).lower()
    if len(t) != 40:
        return None
    for k in known:
        kk = strip0x(k).lower()
        if kk == t or len(kk) != 40:
            continue
        if t[:4] == kk[:4] and t[-4:] == kk[-4:]:
            return "0x" + kk
    return None


def evaluate(tx: Transaction, decoded: DecodedCall,
             sim: SimulationResult | None = None) -> RiskReport:
    findings: list[Finding] = []
    escalate = False

    # --- un-decodable / unknown interactions: can't assess -> escalate ---
    if decoded.decode_error:
        escalate = True
        findings.append(Finding("DECODE_ERROR", 0.5,
            f"calldata could not be fully decoded: {decoded.decode_error}"))
    elif not decoded.known and strip0x(tx.data or ""):
        escalate = True
        findings.append(Finding("UNKNOWN_SELECTOR", 0.4,
            f"interacts with an unrecognized function ({decoded.selector}); "
            "intent cannot be verified before signing"))

    a = decoded.args

    if decoded.function in ("approve", "increaseAllowance"):
        amount = a.get("amount", a.get("addedValue", 0))
        spender = a.get("spender", "")
        if amount >= _UNLIMITED_THRESHOLD:
            findings.append(Finding("UNLIMITED_APPROVAL", 0.8,
                f"grants an effectively unlimited token allowance to {spender} "
                f"(amount~{'MAX_UINT256' if amount >= MAX_UINT256 else hex(amount)})"))
        elif amount > 0:
            findings.append(Finding("TOKEN_APPROVAL", 0.2,
                f"grants a bounded token allowance of {amount} to {spender}"))

    elif decoded.function == "setApprovalForAll":
        if a.get("approved") is True:
            findings.append(Finding("OPERATOR_APPROVAL", 0.8,
                f"grants an NFT collection operator approval to {a.get('operator','')} "
                "(can move ALL tokens in the collection); classic NFT-drainer step"))
        else:
            findings.append(Finding("OPERATOR_REVOKE", 0.0,
                "revokes operator approval (safe)"))

    elif decoded.function == "permit":
        value = a.get("value", 0)
        sev = 0.7 if value >= _UNLIMITED_THRESHOLD else 0.4
        findings.append(Finding("GASLESS_PERMIT", sev,
            f"gasless off-chain approval (permit) to {a.get('spender','')} "
            f"for {'unlimited' if value >= _UNLIMITED_THRESHOLD else value}; "
            "often used in phishing to approve without an on-chain tx"))

    elif decoded.function == "transferFrom":
        frm = (a.get("from") or "").lower()
        if tx.frm and frm and frm != tx.frm.lower():
            findings.append(Finding("PULL_FROM_OTHER", 0.5,
                f"pulls tokens from {a.get('from')} (not the signer) to {a.get('to')}; "
                "only valid if a prior approval exists"))

    # --- address poisoning on the recipient (transfer/transferFrom) ---
    recipient = a.get("to") or (tx.to if not decoded.known else None)
    if recipient and tx.recent_counterparties:
        match = _looks_poisoned(recipient, tx.recent_counterparties)
        if match:
            findings.append(Finding("ADDRESS_POISONING", 0.75,
                f"recipient {recipient} mimics a known address {match} "
                "(same first/last 4 chars) — likely address-poisoning"))

    # --- native value transfer ---
    if tx.value and tx.value > 0 and not decoded.known:
        # irreversible + unknown recipient: large sends warn, dust does not
        sev = 0.3 if tx.value >= 10**18 else 0.1
        findings.append(Finding("NATIVE_VALUE", sev,
            f"sends {tx.value} wei of native currency to {tx.to}"))

    # --- simulation signal ---
    if sim and sim.available and sim.reverts:
        findings.append(Finding("SIMULATION_REVERT", 0.3,
            f"transaction reverts in simulation: {sim.revert_reason}"))

    score = _noisy_or([f.severity for f in findings])

    if escalate:
        decision = Decision.ESCALATE
    elif score >= BLOCK_AT:
        decision = Decision.BLOCK
    elif score >= WARN_AT:
        decision = Decision.WARN
    else:
        decision = Decision.ALLOW

    rationale = _rationale(decision, findings)
    return RiskReport(tx=tx, decoded=decoded, findings=findings,
                      score=round(score, 4), decision=decision, rationale=rationale)


def _rationale(decision: Decision, findings: list[Finding]) -> str:
    if not findings:
        return "No risk signals detected in the decoded call."
    top = sorted(findings, key=lambda f: f.severity, reverse=True)[:3]
    reasons = "; ".join(f.message for f in top)
    return f"{decision.value}: {reasons}"
