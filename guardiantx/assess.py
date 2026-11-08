"""Evidence assessor: the agent's collected observations -> findings + raw score.

Starts from the Phase-1 rule findings on the (possibly ABI-re-decoded) call, then
lets tool evidence discount or add to them: a verified spender defuses an
unlimited approval, a clean simulation defuses an unknown selector, a hidden
outflow or a scam-listed counterparty adds risk. Only TRUSTED fields are used;
untrusted metadata contributes solely through the sanitizer's injection flag.

Also reports which required evidence is missing (the verifier escalates on it).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import DecodedCall, Finding, Transaction
from .encoding import strip0x
from .rules import _UNLIMITED_THRESHOLD, _looks_poisoned, _noisy_or, evaluate

APPROVAL_FNS = {"approve", "increaseAllowance", "permit", "setApprovalForAll"}


@dataclass
class Evidence:
    decoded: dict | None = None
    lookups: dict[str, dict] = field(default_factory=dict)
    proxies: dict[str, dict] = field(default_factory=dict)
    sim: dict | None = None
    allowances: list[dict] = field(default_factory=list)
    injection_hits: list[dict] = field(default_factory=list)

    def record(self, tool: str, args: dict, obs: dict):
        if "error" in obs:
            return
        if tool == "decode_calldata" and (self.decoded is None or obs.get("known")):
            self.decoded = obs
        elif tool == "lookup_address":
            self.lookups[obs["address"]] = obs
        elif tool == "resolve_proxy":
            self.proxies[obs["address"]] = obs
        elif tool == "simulate_tx" and obs.get("available"):
            self.sim = obs
        elif tool == "inspect_allowance":
            self.allowances.append(obs)


def counterparties(tx: Transaction, dec: dict | None) -> dict[str, str]:
    """role -> address the user is dealing with (spender / recipient / source)."""
    out = {}
    if dec and dec.get("known"):
        a = dec["args"]
        fn = dec["function"]
        if fn in APPROVAL_FNS:
            amt = a.get("amount", a.get("addedValue", a.get("value", 1)))
            if fn == "setApprovalForAll":
                amt = 1 if a.get("approved") else 0
            if amt:
                out["spender"] = a.get("spender") or a.get("operator")
        elif fn in ("transfer", "transferFrom"):
            out["recipient"] = a.get("to")
            if fn == "transferFrom" and tx.frm and a.get("from", "").lower() != tx.frm.lower():
                out["source"] = a.get("from")
    if tx.value and not strip0x(tx.data or ""):
        out["recipient"] = tx.to
    return {k: v.lower() for k, v in out.items() if v}


def assess(tx: Transaction, ev: Evidence) -> tuple[list[Finding], float, bool, list[str]]:
    """Returns (findings, raw_score, cannot_assess, missing_required_evidence)."""
    if ev.decoded is None:  # nothing was investigated (planner/tool failure): a human must look
        return ([Finding("NOT_INVESTIGATED", 0.0, "the transaction was never decoded; no evidence collected", "assess")],
                0.0, True, ["decode_calldata"])
    d = ev.decoded
    dc = DecodedCall(selector=d["selector"], function=d["function"], signature=d["signature"],
                     args=d["args"], known=d["known"], decode_error=d.get("decode_error"))
    base = evaluate(tx, dc, None)
    cp = counterparties(tx, d)
    sim = ev.sim
    signer = (tx.frm or "").lower()
    findings: list[Finding] = []
    cannot_assess = False

    # where the signer's assets are *supposed* to go
    expected = {tx.to.lower(), *cp.values()}
    hidden = [c for c in (sim or {}).get("asset_changes", [])
              if c["from"] == signer and c["to"] not in expected]

    spender_info = ev.lookups.get(cp.get("spender", ""), {})
    trusted_spender = spender_info.get("verified") and not spender_info.get("scam_listed")

    for f in base.findings:
        if f.code in ("UNLIMITED_APPROVAL", "OPERATOR_APPROVAL", "GASLESS_PERMIT", "TOKEN_APPROVAL") and trusted_spender:
            findings.append(Finding(f.code + "_TRUSTED", round(f.severity * 0.15, 3),
                                    f.message + f" (spender is verified: {spender_info.get('label')})", "assess"))
        elif f.code in ("UNKNOWN_SELECTOR", "DECODE_ERROR"):
            if sim and not sim.get("reverts") and not hidden:
                findings.append(Finding("UNKNOWN_SELECTOR_SIMULATED", 0.2,
                                        f.message + "; simulation shows no unexpected asset movement", "assess"))
            else:
                findings.append(f)
                cannot_assess = cannot_assess or sim is None
        elif f.code == "PULL_FROM_OTHER" and any(
                int(a["allowance"]) >= int(d["args"].get("amount", 0)) and a["spender"] == signer
                for a in ev.allowances):
            continue  # covered by an existing allowance: legitimate spend
        elif f.code == "ADDRESS_POISONING":
            continue  # re-checked below over every counterparty
        else:
            findings.append(f)

    # --- reputation of each counterparty ---
    for role, a in cp.items():
        info = ev.lookups.get(a)
        if info is None:
            continue
        if info.get("scam_listed"):
            findings.append(Finding("SCAM_LISTED", 0.95, f"{role} {a} is on a scam list", "lookup_address"))
            continue
        if info.get("verified"):
            continue
        if role == "spender":
            if info["kind"] == "eoa":
                findings.append(Finding("EOA_SPENDER", 0.55, f"approval granted to an externally-owned account {a}", "lookup_address"))
            else:
                findings.append(Finding("UNVERIFIED_SPENDER", 0.3, f"spender {a} is an unverified contract", "lookup_address"))
        if not info.get("known") or info.get("fresh"):
            findings.append(Finding("FRESH_COUNTERPARTY", 0.35 if role == "spender" else 0.25,
                                    f"{role} {a} has almost no on-chain history", "lookup_address"))
        if tx.recent_counterparties:
            m = _looks_poisoned(a, tx.recent_counterparties)
            if m:
                findings.append(Finding("ADDRESS_POISONING", 0.75,
                                        f"{role} {a} mimics recent counterparty {m} (same first/last 4 chars)", "assess"))

    # --- the called contract itself ---
    tgt = ev.lookups.get(tx.to.lower())
    if tgt and tgt.get("scam_listed") and "recipient" not in cp:
        findings.append(Finding("SCAM_LISTED", 0.95, f"target contract {tx.to} is on a scam list", "lookup_address"))
    if tgt and tgt["kind"] == "contract" and not tgt.get("verified") and not d.get("known"):
        findings.append(Finding("UNVERIFIED_TARGET", 0.3, f"unknown function on an unverified contract {tx.to}", "lookup_address"))
    px = ev.proxies.get(tx.to.lower())
    if px and px.get("is_proxy"):
        if not px.get("impl_verified"):
            findings.append(Finding("PROXY_IMPL_UNVERIFIED", 0.5,
                                    f"proxy {tx.to} delegates to unverified implementation {px['implementation']}", "resolve_proxy"))
        if (px.get("impl_age_days") or 999) < 7:
            findings.append(Finding("RECENT_UPGRADE", 0.4,
                                    f"proxy implementation changed {px['impl_age_days']} day(s) ago", "resolve_proxy"))

    # --- simulation ---
    if sim:
        if sim.get("reverts"):
            findings.append(Finding("SIMULATION_REVERT", 0.3, f"reverts in simulation: {sim.get('revert_reason')}", "simulate_tx"))
        for c in hidden:
            dest = ev.lookups.get(c["to"], {})
            tag = " (scam-listed)" if dest.get("scam_listed") else ""
            findings.append(Finding("HIDDEN_OUTFLOW", 0.9,
                                    f"simulation: {c['amount']} of {c['asset']} leaves the wallet to {c['to']}{tag}, "
                                    "which the call does not name", "simulate_tx"))
        for ap in sim.get("approval_changes", []):
            if int(ap.get("amount", 0) or 0) >= _UNLIMITED_THRESHOLD and not trusted_spender and not any(
                    f.code == "UNLIMITED_APPROVAL" for f in findings):
                findings.append(Finding("UNLIMITED_APPROVAL", 0.8, "simulation shows an unlimited approval", "simulate_tx"))

    if ev.injection_hits:
        cats = sorted({c for h in ev.injection_hits for c in h["categories"]})
        findings.append(Finding("INJECTION_ATTEMPT", 0.6,
                                f"untrusted on-chain text tried to instruct the wallet ({', '.join(cats)})", "guard"))

    # --- required evidence (checked by the verifier) ---
    missing = []
    for role, a in cp.items():
        if a not in ev.lookups:
            missing.append(f"lookup_address({role})")
    if not d.get("known") and (tx.data or "0x") not in ("", "0x") and sim is None:
        missing.append("simulate_tx")
    if tgt and tgt.get("is_proxy") and tx.to.lower() not in ev.proxies:
        missing.append("resolve_proxy(target)")
    if ev.decoded is None:
        missing.append("decode_calldata")

    return findings, _noisy_or([f.severity for f in findings]), cannot_assess, missing
