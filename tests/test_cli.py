"""CLI tests: exit codes and input-error handling. Run standalone or via pytest."""
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from guardiantx.cli import main


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _tmp(content):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def test_example_file_produces_a_decision():
    rc, out, _ = _run(["--file", os.path.join(ROOT, "examples", "unlimited_approve.json")])
    assert rc in (0, 2) and "decision=" in out


def test_json_output_is_parseable():
    rc, out, _ = _run(["--file", os.path.join(ROOT, "examples", "unlimited_approve.json"), "--json"])
    assert json.loads(out)["decision"] in ("ALLOW", "WARN", "BLOCK", "ESCALATE")


def test_missing_file_is_a_clean_error():
    rc, out, err = _run(["--file", os.path.join(ROOT, "does_not_exist.json")])
    assert rc == 1 and err.startswith("error: cannot read") and not out


def test_invalid_json_is_a_clean_error():
    path = _tmp('{"to": "0xabc",')
    try:
        rc, _, err = _run(["--file", path])
    finally:
        os.remove(path)
    assert rc == 1 and "not valid JSON" in err


def test_missing_to_is_a_clean_error():
    for content in ('{"data": "0x095ea7b3"}', "[1, 2]"):
        path = _tmp(content)
        try:
            rc, _, err = _run(["--file", path])
        finally:
            os.remove(path)
        assert rc == 1 and '"to" address' in err, content


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("ok", name)
    print("all cli tests passed")
