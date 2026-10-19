"""Command-line entry point: analyze one transaction.

    python -m guardiantx.cli --file tx.json
    echo '{"to":"0x...","data":"0x095ea7b3..."}' | python -m guardiantx.cli
    python -m guardiantx.cli --file tx.json --json      # machine-readable
    python -m guardiantx.cli --file tx.json --simulate --explain
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
    args = ap.parse_args(argv)

    try:  # make non-ASCII output safe on Windows consoles (cp1252)
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    raw = open(args.file, encoding="utf-8").read() if args.file else sys.stdin.read()
    tx = json.loads(raw)

    report = analyze_dict(tx, simulate=args.simulate, explain=args.explain)
    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(_render(report))
    # exit code doubles as a signal for scripts: 0 allow/warn, 2 block/escalate
    return 0 if report.decision.value in ("ALLOW", "WARN") else 2


if __name__ == "__main__":
    raise SystemExit(main())
