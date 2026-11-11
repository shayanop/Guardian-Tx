"""Command-line entry point: analyze one transaction.

    python -m guardiantx.cli --file tx.json
    echo '{"to":"0x...","data":"0x095ea7b3..."}' | python -m guardiantx.cli
    python -m guardiantx.cli --file tx.json --json      # machine-readable
    python -m guardiantx.cli --file tx.json --simulate --explain
    python -m guardiantx.cli --file tx.json --agent --trace           # Phase-2 agent
    python -m guardiantx.cli --file tx.json --agent --planner llm     # LLM planner (NVIDIA NIM)

Exit code: 0 = ALLOW/WARN, 2 = BLOCK/ESCALATE, 1 = bad input or configuration.
"""
from __future__ import annotations

import argparse
import json
import sys

from .pipeline import analyze_dict

_ICON = {"ALLOW": "[ALLOW]", "WARN": "[WARN ]", "BLOCK": "[BLOCK]", "ESCALATE": "[ESCL ]"}


def _render(report) -> str:
    d = report.to_dict()
    lines = [
        f"{_ICON.get(d['decision'], '')} decision={d['decision']}  risk={d['score']}",
        f"  to:       {d['tx']['to']}",
        f"  function: {d['decoded']['signature'] or d['decoded']['selector']}",
    ]
    if d["decoded"]["args"]:
        lines.append(f"  args:     {d['decoded']['args']}")
    lines.append("  findings:")
    for f in d["findings"]:
        lines.append(f"    - [{f['severity']}] {f['code']}: {f['message']}")
    if not d["findings"]:
        lines.append("    - (none)")
    lines.append(f"  rationale: {d['rationale']}")
    if d.get("explanation"):
        lines.append(f"  explanation: {d['explanation']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="guardiantx", description="Pre-signing tx risk analysis")
    ap.add_argument("--file", help="JSON file with one transaction (default: stdin)")
    ap.add_argument("--json", action="store_true", help="emit the full report as JSON")
    ap.add_argument("--simulate", action="store_true", help="run Anvil/RPC simulation if available")
    ap.add_argument("--explain", action="store_true", help="add an LLM explanation if available")
    ap.add_argument("--agent", action="store_true", help="use the Phase-2 investigating agent")
    ap.add_argument("--planner", default="policy", choices=["policy", "fixed", "llm"], help="agent planner")
    ap.add_argument("--world", default=None, help="chain-environment JSON (default: data/world.json)")
    ap.add_argument("--trace", action="store_true", help="print the agent trajectory")
    args = ap.parse_args(argv)

    try:  # make non-ASCII output safe on Windows consoles (cp1252)
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    tx, err = _read_tx(args.file)
    if err:
        print(f"error: {err}", file=sys.stderr)
        return 1

    trace = None
    if args.agent:
        try:
            report, trace = _run_agent(tx, args)
        except RuntimeError as e:  # e.g. --planner llm without NVIDIA_API_KEY
            print(f"error: {e}", file=sys.stderr)
            return 1
    else:
        report = analyze_dict(tx, simulate=args.simulate, explain=args.explain)
    if args.json:
        print(json.dumps({**report.to_dict(), **({"trace": trace} if trace else {})}, indent=2, default=str))
    else:
        if trace and args.trace:
            for st in trace["steps"]:
                print(f"  step {st['step']}: {st['thought']}\n    -> {st['tool']}({st['args']})")
            print()
        print(_render(report))
    # exit code doubles as a signal for scripts: 0 allow/warn, 2 block/escalate
    return 0 if report.decision.value in ("ALLOW", "WARN") else 2


def _read_tx(path):
    """Load one transaction object from `path` (or stdin). Returns (tx, error)."""
    try:
        if path:
            with open(path, encoding="utf-8") as fh:
                raw = fh.read()
        else:
            raw = sys.stdin.read()
    except OSError as e:
        return None, f"cannot read {path}: {e.strerror or e}"
    try:
        tx = json.loads(raw)
    except json.JSONDecodeError as e:
        return None, f"input is not valid JSON ({e.msg} at line {e.lineno}, column {e.colno})"
    if not isinstance(tx, dict) or not tx.get("to"):
        return None, 'input must be a JSON object with a "to" address'
    return tx, None


def _run_agent(tx: dict, args):
    import os
    from .agent import AgentConfig, run_agent, tx_from_row
    from .calibration import Calibrator
    from .world import DEFAULT_WORLD, World
    cal_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results", "calibration.json")
    cal = Calibrator.load(cal_path) if os.path.exists(cal_path) else Calibrator.identity()
    return run_agent(tx_from_row(tx), World.load(args.world or DEFAULT_WORLD),
                     AgentConfig(planner=args.planner, calibrator=cal))


if __name__ == "__main__":
    raise SystemExit(main())
