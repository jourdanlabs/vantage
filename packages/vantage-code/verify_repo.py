#!/usr/bin/env python3
"""Full-repo verifier — pytest against a real checkout, no model.

PROVEN iff the same test fails at the buggy SHA and passes at the fixed SHA
when imported from the live module (not the extracted `subject.py` slice).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rewrite_subject_import(test_src: str, module: str) -> str:
    rewritten, n = re.subn(
        r"^from subject import (.+)$",
        rf"from {module} import \1",
        test_src,
        flags=re.M,
    )
    rewritten, n2 = re.subn(
        r"^import subject\b",
        f"import {module} as subject",
        rewritten,
        flags=re.M,
    )
    if n == 0 and n2 == 0:
        raise ValueError("repro test has no `from subject import ...` / `import subject` line to rewrite")
    return rewritten


def run_pytest_repo(repo_root: Path, test_src: str, timeout_s: int = 20) -> dict:
    tmp = Path(tempfile.mkdtemp(prefix="vantage-code-repo-"))
    try:
        (tmp / "test_repro.py").write_text(test_src)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(repo_root) + os.pathsep + env.get("PYTHONPATH", "")
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "--tb=line", "test_repro.py"],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
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


def verify_repo(
    *,
    buggy_root: Path,
    fixed_root: Path,
    test_py: Path,
    module: str,
    timeout_s: int = 20,
) -> dict:
    test_src = rewrite_subject_import(test_py.read_text(), module)
    buggy_run = run_pytest_repo(buggy_root, test_src, timeout_s=timeout_s)
    fixed_run = run_pytest_repo(fixed_root, test_src, timeout_s=timeout_s)
    verdict = (
        "PROVEN"
        if buggy_run["status"] == "fail" and fixed_run["status"] == "pass"
        else "UNVERIFIED"
    )
    reason = (
        "fail_buggy_pass_fixed"
        if verdict == "PROVEN"
        else "not_fail_buggy_and_pass_fixed"
    )
    return {
        "verdict": verdict,
        "reason": reason,
        "module": module,
        "test_sha256": sha256_file(test_py),
        "buggy": {k: buggy_run[k] for k in ("status", "returncode", "timeout")},
        "fixed": {k: fixed_run[k] for k in ("status", "returncode", "timeout")},
        "buggy_tail": buggy_run["stdout"][-400:] + buggy_run["stderr"][-400:],
        "fixed_tail": fixed_run["stdout"][-400:] + fixed_run["stderr"][-400:],
        "rewritten_test": test_src,
    }


def main() -> int:
    if len(sys.argv) != 5:
        print(
            "usage: verify_repo.py <buggy-root> <fixed-root> <repro_test.py> <module.path>",
            file=sys.stderr,
        )
        return 2
    row = verify_repo(
        buggy_root=Path(sys.argv[1]),
        fixed_root=Path(sys.argv[2]),
        test_py=Path(sys.argv[3]),
        module=sys.argv[4],
    )
    print(json.dumps(row, indent=2, sort_keys=True))
    return 0 if row["verdict"] == "PROVEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
