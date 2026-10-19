"""End-to-end pipeline + dataset integrity tests."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from guardiantx.contracts import Decision
from guardiantx.pipeline import analyze_dict

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "data", "seed_transactions.jsonl")


def _rows():
    with open(DATA, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def test_report_is_json_serializable():
    rows = _rows()
    r = analyze_dict(rows[0])
    json.dumps(r.to_dict())  # must not raise


def test_every_row_produces_valid_decision():
    for row in _rows():
        r = analyze_dict(row)
        assert isinstance(r.decision, Decision)
        assert 0.0 <= r.score <= 1.0


def test_baseline_catches_clear_drainers():
    # the unambiguous malicious rows must not be ALLOWed
    clear = {"m01", "m02", "m03", "m04", "m05", "m06", "m07", "m09", "m10", "m11", "m12"}
    rows = {row["id"]: row for row in _rows()}
    for rid in clear:
        r = analyze_dict(rows[rid])
        assert r.decision != Decision.ALLOW, f"{rid} was ALLOWed: {r.rationale}"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all pipeline tests passed")
