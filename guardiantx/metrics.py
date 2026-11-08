"""Detection, calibration, and selective-prediction metrics (stdlib only)."""
from __future__ import annotations

import math
import random
import statistics

FLAG = {"BLOCK", "ESCALATE"}


def detection(labels: list[int], decisions: list[str]) -> dict:
    """labels: 1 = malicious. A tx is flagged when the decision is BLOCK or ESCALATE."""
    tp = fp = tn = fn = 0
    for y, d in zip(labels, decisions):
        p = d in FLAG
        tp += y and p
        fp += (not y) and p
        tn += (not y) and not p
        fn += y and not p
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    n = len(labels)
    benign = fp + tn
    hard_blocks = sum(1 for y, d in zip(labels, decisions) if not y and d == "BLOCK")
    return dict(n=n, tp=tp, fp=fp, tn=tn, fn=fn, accuracy=(tp + tn) / n if n else 0.0,
                precision=prec, recall=rec, f1=2 * prec * rec / (prec + rec) if prec + rec else 0.0,
                false_flag_rate=fp / benign if benign else 0.0,
                false_block_rate=hard_blocks / benign if benign else 0.0,
                escalation_rate=sum(d == "ESCALATE" for d in decisions) / n if n else 0.0)


def ece(labels: list[int], probs: list[float], bins: int = 10) -> float:
    total, n = 0.0, len(labels)
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        idx = [i for i, p in enumerate(probs) if lo <= p < hi or (b == bins - 1 and p == 1.0)]
        if idx:
            conf = sum(probs[i] for i in idx) / len(idx)
            acc = sum(labels[i] for i in idx) / len(idx)
            total += len(idx) / n * abs(conf - acc)
    return total


def brier(labels: list[int], probs: list[float]) -> float:
    return sum((p - y) ** 2 for y, p in zip(labels, probs)) / len(labels)


def risk_coverage(labels: list[int], probs: list[float]) -> dict:
    """Selective classification: abstain on the least-confident items first.
    Returns the curve and AURC (area under risk-coverage; lower is better)."""
    conf = [max(p, 1 - p) for p in probs]
    order = sorted(range(len(labels)), key=lambda i: -conf[i])
    curve, errs = [], 0
    for k, i in enumerate(order, 1):
        errs += int((probs[i] >= 0.5) != bool(labels[i]))
        curve.append((k / len(order), errs / k))
    aurc = sum(r for _, r in curve) / len(curve)
    return {"aurc": aurc, "curve": [(round(c, 3), round(r, 4)) for c, r in curve[::max(1, len(curve) // 20)]]}


def selective(labels: list[int], decisions: list[str]) -> dict:
    """Accuracy on the items the system decided itself (ESCALATE = abstain)."""
    kept = [(y, d) for y, d in zip(labels, decisions) if d != "ESCALATE"]
    if not kept:
        return {"coverage": 0.0, "selective_accuracy": 0.0}
    acc = sum((d == "BLOCK") == bool(y) for y, d in kept) / len(kept)
    return {"coverage": len(kept) / len(labels), "selective_accuracy": acc}


def bootstrap_ci(labels: list[int], decisions: list[str], metric: str = "f1", n: int = 1000, seed: int = 0) -> tuple[float, float]:
    rng = random.Random(seed)
    idx = list(range(len(labels)))
    vals = []
    for _ in range(n):
        s = [rng.choice(idx) for _ in idx]
        vals.append(detection([labels[i] for i in s], [decisions[i] for i in s])[metric])
    vals.sort()
    return vals[int(0.025 * n)], vals[int(0.975 * n) - 1]


def mean_std(xs: list[float]) -> tuple[float, float]:
    return (statistics.fmean(xs), statistics.stdev(xs) if len(xs) > 1 else 0.0)


def logit(p: float, eps: float = 1e-4) -> float:
    p = min(max(p, eps), 1 - eps)
    return math.log(p / (1 - p))
