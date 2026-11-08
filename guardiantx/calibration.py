"""G2 - risk calibration and principled abstention.

The raw noisy-OR score is a severity aggregate, not a probability. We fit Platt
scaling (p = sigmoid(a * logit(raw) + b)) on the DEV split only, then pick the
decision thresholds on dev:

* t_block - smallest threshold whose dev false-BLOCK rate on benign tx <= target
            (5% in the proposal; we aim at 2% for margin),
* t_low   - lowest threshold whose dev rate of benign tx sent to human review
            (ESCALATE band) stays within the review budget (10%).
Between them the system ESCALATEs to a human: that band is the abstention region.

Platt scaling is kept only if it beats the identity map on 5-fold CV Brier score
within dev (`method` records the choice): a scorer that is already calibrated
should not be "corrected".

`Calibrator.identity()` reproduces the uncalibrated Phase-1 policy (fixed bands
0.25 / 0.60, no abstention band) for the G2 ablation.
"""
from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass

from .contracts import Decision
from .metrics import logit


@dataclass
class Calibrator:
    a: float = 1.0
    b: float = 0.0
    t_low: float = 0.25
    t_block: float = 0.60
    calibrated: bool = True
    abstain: bool = True
    method: str = "platt"

    @classmethod
    def identity(cls) -> "Calibrator":
        return cls(calibrated=False, abstain=False, method="uncalibrated")

    def prob(self, raw: float) -> float:
        if not self.calibrated:
            return raw
        return 1 / (1 + math.exp(-(self.a * logit(raw) + self.b)))

    def decide(self, raw: float, cannot_assess: bool, has_material_finding: bool) -> tuple[float, Decision]:
        p = self.prob(raw)
        if p >= self.t_block:
            return p, Decision.BLOCK
        if cannot_assess:
            return p, Decision.ESCALATE
        if p >= self.t_low:
            return p, Decision.ESCALATE if self.abstain else Decision.WARN
        return p, Decision.WARN if has_material_finding else Decision.ALLOW

    # --- fitting (dev split only) ---------------------------------------------
    @staticmethod
    def _platt(raws, labels, iters=3000, lr=0.1):
        xs = [logit(r) for r in raws]
        a, b, n = 1.0, 0.0, len(xs)
        for _ in range(iters):  # logistic regression by gradient descent (1 feature)
            ga = gb = 0.0
            for x, y in zip(xs, labels):
                p = 1 / (1 + math.exp(-(a * x + b)))
                ga += (p - y) * x
                gb += (p - y)
            a -= lr * ga / n
            b -= lr * gb / n
        return a, b

    @classmethod
    def fit(cls, raws: list[float], labels: list[int], *, max_false_block: float = 0.02,
            max_benign_escalation: float = 0.10, folds: int = 5) -> "Calibrator":
        # method selection: 5-fold CV Brier, Platt vs identity (dev data only)
        idx = list(range(len(raws)))
        err = {"platt": 0.0, "identity": 0.0}
        for k in range(folds):
            te = idx[k::folds]
            tr = [i for i in idx if i % folds != k]
            a, b = cls._platt([raws[i] for i in tr], [labels[i] for i in tr])
            for i in te:
                err["platt"] += (cls(a=a, b=b).prob(raws[i]) - labels[i]) ** 2
                err["identity"] += (raws[i] - labels[i]) ** 2
        if err["platt"] < err["identity"]:
            a, b = cls._platt(raws, labels)
            c = cls(a=a, b=b, method="platt")
        else:
            c = cls(calibrated=False, method="identity")
        probs = sorted({c.prob(r) for r in raws})
        benign = [c.prob(r) for r, y in zip(raws, labels) if not y]
        nb = max(1, len(benign))
        # t_block: lowest candidate meeting the false-block budget on dev
        c.t_block = next((t for t in probs if sum(p >= t for p in benign) / nb <= max_false_block), 1.0)
        # t_low: lowest threshold keeping benign escalations (t_low <= p < t_block) within budget
        c.t_low = next((t for t in probs if t > 0 and t <= c.t_block
                        and sum(t <= p < c.t_block for p in benign) / nb <= max_benign_escalation), c.t_block)
        return c

    def save(self, path: str):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self), f, indent=2)

    @classmethod
    def load(cls, path: str) -> "Calibrator":
        with open(path, encoding="utf-8") as f:
            return cls(**json.load(f))
