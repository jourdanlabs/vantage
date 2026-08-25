#!/usr/bin/env python3
"""VANTAGE CODE verifier — deterministic, no model.

A generated pytest either FAILS on buggy + PASSES on fixed (PROVEN),
or it does not (UNVERIFIED). The model is not imported here on purpose.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

VERDICTS = ("PROVEN", "DEMONSTRATED", "UNVERIFIED")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def run_pytest(subject_py: Path, test_py: Path, timeout_s: int = 12) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="vantage-code-"))
    try:
        (tmp / "subject.py").write_bytes(subject_py.read_bytes())
        (tmp / "test_repro.py").write_bytes(test_py.read_bytes())
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=line", "test_repro.py"],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        status = "pass" if proc.returncode == 0 else "fail"
        return {
            "status": status,
            "returncode": proc.returncode,
            "stdout": (proc.stdout or "")[-2000:],
            "stderr": (proc.stderr or "")[-2000:],
            "timeout": False,
        }
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "fail",
            "returncode": None,
            "stdout": (exc.stdout or "")[-2000:] if isinstance(exc.stdout, str) else "",
            "stderr": "TIMEOUT",
            "timeout": True,
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def verdict_for(buggy: dict, fixed: dict) -> str:
    if buggy["status"] == "fail" and fixed["status"] == "pass":
        return "PROVEN"
    return "UNVERIFIED"


def verify_case(case_dir: Path, timeout_s: int = 8) -> dict:
    test_py = case_dir / "repro_test.py"
    buggy_py = case_dir / "buggy.py"
    correct_py = case_dir / "correct.py"
    if not test_py.exists() or test_py.stat().st_size == 0:
        return {
            "case": case_dir.name,
            "verdict": "UNVERIFIED",
            "reason": "no_repro_test",
            "test_sha256": None,
        }
    test_sha = sha256_file(test_py)
    buggy_run = run_pytest(buggy_py, test_py, timeout_s=timeout_s)
    fixed_run = run_pytest(correct_py, test_py, timeout_s=timeout_s)
    same_source = sha256_file(buggy_py) == sha256_file(correct_py)
    verdict = verdict_for(buggy_run, fixed_run)
    if same_source and verdict == "PROVEN":
        # Structural refusal: differential proof requires two different programs.
        verdict = "UNVERIFIED"
        reason = "same_source_not_differential"
    else:
        reason = "fail_buggy_pass_fixed" if verdict == "PROVEN" else "not_fail_buggy_and_pass_fixed"
    return {
        "case": case_dir.name,
        "verdict": verdict,
        "reason": reason,
        "same_source": same_source,
        "test_sha256": test_sha,
        "buggy_sha256": sha256_file(buggy_py),
        "correct_sha256": sha256_file(correct_py),
        "buggy": {k: buggy_run[k] for k in ("status", "returncode", "timeout")},
        "fixed": {k: fixed_run[k] for k in ("status", "returncode", "timeout")},
        "buggy_tail": buggy_run["stdout"][-400:] + buggy_run["stderr"][-400:],
        "fixed_tail": fixed_run["stdout"][-400:] + fixed_run["stderr"][-400:],
    }


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: verify.py <case-dir> [<case-dir>...]")
        return 2
    rows = []
    for arg in sys.argv[1:]:
        row = verify_case(Path(arg))
        rows.append(row)
        print(json.dumps(row, sort_keys=True))
    proven = sum(1 for r in rows if r["verdict"] == "PROVEN")
    print(json.dumps({"n": len(rows), "proven": proven}, sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
