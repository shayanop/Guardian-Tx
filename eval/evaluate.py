"""Run the baseline over the seed set and report initial results.

    python eval/evaluate.py                      # uses data/seed_transactions.jsonl
    python eval/evaluate.py --data path.jsonl --json

Binary detection mapping: a transaction is FLAGGED (predicted malicious) when the
baseline returns BLOCK or ESCALATE. ALLOW/WARN are treated as "pass" -- WARN is a
soft nudge, not a stop -- so a malicious tx that only earns WARN counts as a miss.
This deliberately understates the baseline and motivates the proposed agent.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardiantx.pipeline import analyze_dict  # noqa: E402

FLAG = {"BLOCK", "ESCALATE"}
DEFAULT_DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "..", "data", "seed_transactions.jsonl")


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def run(rows):
    tp = fp = tn = fn = 0
    per_cat = defaultdict(lambda: [0, 0])  # category -> [correct, total]
    dist = defaultdict(int)
    misses = []
    for row in rows:
        report = analyze_dict(row)
        decision = report.decision.value
        dist[decision] += 1
        predicted_mal = decision in FLAG
        actual_mal = row["label"] == "malicious"
        correct = predicted_mal == actual_mal
        per_cat[row.get("category", "?")][0] += int(correct)
        per_cat[row.get("category", "?")][1] += 1
        if actual_mal and predicted_mal:
            tp += 1
        elif not actual_mal and predicted_mal:
            fp += 1
        elif not actual_mal and not predicted_mal:
            tn += 1
        else:
            fn += 1
        if not correct:
            misses.append((row["id"], row["label"], decision, round(report.score, 3)))
    return dict(tp=tp, fp=fp, tn=tn, fn=fn, per_cat=dict(per_cat), dist=dict(dist),
                misses=misses, n=len(rows))


def metrics(r):
    tp, fp, tn, fn = r["tp"], r["fp"], r["tn"], r["fn"]
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / r["n"] if r["n"] else 0.0
    fbr = fp / (fp + tn) if fp + tn else 0.0  # false-block rate on benign
    return dict(accuracy=acc, precision=prec, recall=rec, f1=f1, false_block_rate=fbr)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DEFAULT_DATA)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    r = run(load(args.data))
    m = metrics(r)

    if args.json:
        print(json.dumps({**r, **m}, indent=2))
        return 0

    print(f"GuardianTx baseline - {r['n']} transactions\n")
    print("Confusion (positive = BLOCK/ESCALATE):")
    print(f"  TP={r['tp']}  FP={r['fp']}  TN={r['tn']}  FN={r['fn']}")
    print("\nMetrics:")
    for k, v in m.items():
        print(f"  {k:<16} {v:.3f}")
    print("\nDecision distribution:")
    for k in ("ALLOW", "WARN", "BLOCK", "ESCALATE"):
        print(f"  {k:<9} {r['dist'].get(k, 0)}")
    print("\nPer-category accuracy:")
    for cat, (c, t) in sorted(r["per_cat"].items()):
        print(f"  {cat:<20} {c}/{t}")
    if r["misses"]:
        print("\nMisclassified:")
        for mid, label, dec, score in r["misses"]:
            print(f"  {mid}  actual={label:<9} decision={dec:<9} score={score}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
