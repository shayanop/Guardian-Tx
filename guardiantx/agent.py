"""G3 - the investigating agent: observe -> choose a tool -> act -> repeat -> decide.

    report, trace = run_agent(tx, world, AgentConfig(planner="policy"))

Planners (all share the same tools, assessor, calibrator, and verifier):
* `policy`  - deterministic, data-dependent tool selection (the default; offline and
              reproducible). What it investigates next depends on what it has seen:
              unknown selector -> resolve proxy -> re-decode with the verified ABI ->
              simulate -> look up wherever the simulated assets went.
* `fixed`   - G3 ablation: the same tools in one fixed order on fixed targets, no
              follow-ups (no ABI re-decode, no lookup of simulated outflow destinations).
* `llm`     - an LLM chooses the tools (guardiantx/llm.py): NVIDIA NIM, Groq fallback.
* `compliant` wrapper - the worst-case reasoner for G1: obeys any injected text that
              reaches it (see `CompliantPlanner`).

Every step is logged in the trace: thought, tool, arguments, observation, latency.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Optional

from .assess import Evidence, assess, counterparties
from .calibration import Calibrator
from .contracts import Decision, RiskReport, Transaction, DecodedCall
from .encoding import strip0x
from .guard import echoes_untrusted, verify
from .tools import Toolbox
from .world import World


@dataclass
class AgentConfig:
    planner: str = "policy"            # policy | fixed | llm
    sanitize: bool = True              # G1 sanitizer
    verify: bool = True                # G1 verifier (decision floor + evidence checklist)
    calibrator: Calibrator = field(default_factory=Calibrator.identity)   # G2
    simulation: bool = True
    fault_rate: float = 0.0
    retries: int = 2                   # per-tool retries on transient failure
    max_steps: int = 10
    seed: int = 0


@dataclass
class Action:
    thought: str
    tool: str                       # tool name, or "finish"
    args: dict = field(default_factory=dict)
    proposed: Optional[Decision] = None   # finish only
    rationale: str = ""                   # finish only


class State:
    def __init__(self, tx: Transaction, box: Toolbox):
        self.tx, self.box = tx, box
        self.ev = Evidence()
        self.tried: set[str] = set()
        self.steps: list[dict] = []

    def key(self, tool, args):
        return tool + json.dumps(args, sort_keys=True)

    def untried(self, tool, args):
        return self.key(tool, args) not in self.tried

    @property
    def has_data(self):
        return bool(strip0x(self.tx.data or ""))


class PolicyPlanner:
    """Deterministic data-dependent investigation policy."""

    def next(self, s: State) -> Action:
        tx, ev = s.tx, s.ev
        to = tx.to.lower()
        if ev.decoded is None and s.untried("decode_calldata", {}):
            return Action("Start by decoding what the calldata does.", "decode_calldata")
        dec = ev.decoded or {}
        if (s.has_data or tx.value) and to not in ev.lookups and s.untried("lookup_address", {"address": to}):
            return Action("Check what the target address is (contract? verified? proxy?).", "lookup_address", {"address": to})
        tgt = ev.lookups.get(to, {})
        if tgt.get("is_proxy") and to not in ev.proxies and s.untried("resolve_proxy", {"address": to}):
            return Action("Target is a proxy: find the code that will actually run.", "resolve_proxy", {"address": to})
        px = ev.proxies.get(to, {})
        if not dec.get("known") and s.has_data:
            for src, ok in ((to, tgt.get("has_verified_abi")), (px.get("implementation"), px.get("impl_has_verified_abi"))):
                if src and ok and s.untried("decode_calldata", {"abi_from": src}):
                    return Action(f"Selector unknown to the base DB; re-decode with the verified ABI of {src}.",
                                  "decode_calldata", {"abi_from": src})
        for role, a in counterparties(tx, dec).items():
            if a not in ev.lookups and s.untried("lookup_address", {"address": a}):
                return Action(f"The {role} decides who gets power over the assets; check its reputation.",
                              "lookup_address", {"address": a})
        need_sim = (not dec.get("known") and s.has_data) \
            or (tgt.get("kind") == "contract" and not tgt.get("verified")) \
            or (px.get("is_proxy") and (not px.get("impl_verified") or (px.get("impl_age_days") or 999) < 7))
        if need_sim and ev.sim is None and s.untried("simulate_tx", {}):
            return Action("Static analysis is not conclusive here; simulate to see real asset movements.", "simulate_tx")
        signer = (tx.frm or "").lower()
        expected = {to, *counterparties(tx, dec).values()}
        for c in (ev.sim or {}).get("asset_changes", []):
            if c["from"] == signer and c["to"] not in expected and c["to"] not in ev.lookups \
                    and s.untried("lookup_address", {"address": c["to"]}):
                return Action("Simulation sends assets somewhere the call never named; identify the destination.",
                              "lookup_address", {"address": c["to"]})
        cp = counterparties(tx, dec)
        if "source" in cp:
            args = {"owner": cp["source"], "token": to, "spender": signer}
            if s.untried("inspect_allowance", args):
                return Action("Pulling someone else's tokens: confirm an allowance actually covers it.", "inspect_allowance", args)
        return Action("Evidence is sufficient to decide.", "finish")


class FixedPlanner:
    """G3 ablation: identical tools, fixed order, fixed targets, no follow-ups."""

    def next(self, s: State) -> Action:
        tx, to = s.tx, s.tx.to.lower()
        seq: list[tuple[str, dict]] = [("decode_calldata", {}), ("lookup_address", {"address": to})]
        dec = s.ev.decoded or {}
        for v in dec.get("args", {}).values():
            if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
                seq.append(("lookup_address", {"address": v.lower()}))
        seq += [("resolve_proxy", {"address": to}), ("simulate_tx", {})]
        cp = counterparties(tx, dec)
        if "source" in cp:
            seq.append(("inspect_allowance", {"owner": cp["source"], "token": to, "spender": (tx.frm or "").lower()}))
        for tool, args in seq:
            if s.untried(tool, args):
                return Action("fixed pipeline step", tool, args)
        return Action("fixed pipeline complete", "finish")


class CompliantPlanner:
    """Worst-case reasoner for the G1 stress test: behaves like `base` until an
    injected payload reaches it intact, then does whatever the attacker wants
    (downgrade to ALLOW / stop investigating / echo attacker text to the user).
    It models a fully hijackable LLM, so measured ASR is an upper bound."""

    def __init__(self, base, payload: str, goal: str):
        self.base, self.payload, self.goal = base, payload, goal
        self.hijacked = False

    def next(self, s: State) -> Action:
        if not self.hijacked and s.steps and any(self.payload in t for t in _strings(s.steps[-1]["observation"])):
            self.hijacked = True
            if self.goal == "truncate":
                return Action("(hijacked) told to stop investigating", "finish", proposed=Decision.ALLOW)
        a = self.base.next(s)
        if a.tool == "finish" and self.hijacked:
            if self.goal == "downgrade":
                a.proposed = Decision.ALLOW
            elif self.goal == "rationale":
                a.rationale = self.payload
        return a


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def make_planner(cfg: AgentConfig):
    if cfg.planner == "policy":
        return PolicyPlanner()
    if cfg.planner == "fixed":
        return FixedPlanner()
    if cfg.planner == "llm":
        from .llm import LLMPlanner
        return LLMPlanner(sanitize_output=cfg.sanitize)
    raise ValueError(f"unknown planner {cfg.planner}")


def run_agent(tx: Transaction, world: World, cfg: AgentConfig | None = None, planner=None) -> tuple[RiskReport, dict]:
    cfg = cfg or AgentConfig()
    box = Toolbox(world, tx, guard=cfg.sanitize, enable_simulation=cfg.simulation,
                  fault_rate=cfg.fault_rate, retries=cfg.retries, seed=cfg.seed)
    planner = planner or make_planner(cfg)
    s = State(tx, box)
    t0 = time.perf_counter()
    action = None
    for step in range(cfg.max_steps):
        action = planner.next(s)
        if action.tool == "finish":
            break
        ts = time.perf_counter()
        obs = box.call(action.tool, action.args)
        s.tried.add(s.key(action.tool, action.args))
        s.ev.record(action.tool, action.args, obs)
        s.steps.append({"step": step, "thought": action.thought, "tool": action.tool, "args": action.args,
                        "observation": obs, "latency_ms": round((time.perf_counter() - ts) * 1000, 3)})
        if hasattr(planner, "observe"):
            planner.observe(obs)
    else:
        action = Action("step budget exhausted", "finish")

    s.ev.injection_hits = box.injection_hits
    findings, raw, cannot_assess, missing = assess(tx, s.ev)
    material = any(f.severity >= 0.25 for f in findings)
    prob, ev_decision = cfg.calibrator.decide(raw, cannot_assess, material)
    notes: list[str] = []
    if cfg.verify:
        final, notes = verify(ev_decision, action.proposed, missing)
    else:
        final = action.proposed or ev_decision

    top = sorted(findings, key=lambda f: -f.severity)[:3]
    rationale = f"{final.value}: " + ("; ".join(f.message for f in top) if top else "no risk signals found")
    if action.rationale:
        if cfg.verify and echoes_untrusted(action.rationale, box.untrusted_seen):
            notes.append("reasoner rationale copied untrusted on-chain text; withheld from user")
        else:
            rationale += f" | reasoner: {action.rationale}"
    d = s.ev.decoded or {}
    report = RiskReport(
        tx=tx,
        decoded=DecodedCall(selector=d.get("selector", "0x"), function=d.get("function"),
                            signature=d.get("signature"), args=d.get("args", {}), known=d.get("known", False),
                            decode_error=d.get("decode_error")),
        findings=findings, score=round(prob, 4), decision=final, rationale=rationale)
    trace = {
        "planner": cfg.planner, "steps": s.steps,
        "final": {"raw_score": round(raw, 4), "prob": round(prob, 4), "evidence_decision": ev_decision.value,
                  "proposed": action.proposed.value if action.proposed else None, "decision": final.value,
                  "verifier_notes": notes, "missing_evidence": missing, "cannot_assess": cannot_assess,
                  "findings": [f.to_dict() for f in findings], "finish_thought": action.thought},
        "usage": {"tool_calls": len(s.steps), "tool_attempts": box.calls, "tool_failures": box.failures,
                  "latency_ms": round((time.perf_counter() - t0) * 1000, 3),
                  **getattr(planner, "usage", {})},
    }
    return report, trace


def tx_from_row(row: dict[str, Any]) -> Transaction:
    return Transaction(to=row["to"], data=row.get("data", "0x"), value=int(row.get("value", 0)),
                       frm=row.get("from") or row.get("frm"), chain_id=int(row.get("chain_id", 1)),
                       recent_counterparties=row.get("recent_counterparties", []))
