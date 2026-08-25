#!/usr/bin/env python3
"""Full-repo VERIFY batch — existing finder tests against real checkouts.

Does not reopen extracted UNVERIFIED rows. New board, new seal, pytest only.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from verify_repo import verify_repo  # noqa: E402

CO = Path("/tmp/vantage-code-co")
VANTAGE = HERE.parent.parent


def module_from_source_path(rel: str) -> str:
    p = Path(rel)
    if p.suffix != ".py":
        raise ValueError(rel)
    parts = list(p.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def checkout(repo: str, sha: str, sparse_dir: str) -> Path:
    dest = CO / repo.replace("/", "_") / sha[:12]
    head_ok = False
    if (dest / ".git").exists():
        try:
            head = subprocess.check_output(
                ["git", "-C", str(dest), "rev-parse", "HEAD"], text=True
            ).strip()
            head_ok = head.startswith(sha[:12])
        except subprocess.CalledProcessError:
            head_ok = False
    if head_ok:
        return dest
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        subprocess.run(["git", "-C", str(dest), "init", "-q"], check=True)
        subprocess.run(
            ["git", "-C", str(dest), "remote", "add", "origin", f"https://github.com/{repo}.git"],
            check=True,
        )
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "init", "--cone"], check=True)
        subprocess.run(["git", "-C", str(dest), "sparse-checkout", "set", sparse_dir], check=True)
    subprocess.run(
        ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", sha],
        check=True,
        capture_output=True,
    )
    subprocess.run(["git", "-C", str(dest), "checkout", "--detach", "FETCH_HEAD"], check=True, capture_output=True)
    return dest


def iter_candidates() -> list[Path]:
    rows = []
    root = VANTAGE / "receipts/dev"
    for board in sorted(root.glob("vantage-code-board*")):
        cases = board / "cases"
        if not cases.is_dir():
            continue
        for d in sorted(cases.iterdir()):
            if not d.is_dir() or d.name.startswith("control") or d.name.startswith("_"):
                continue
            test = d / "repro_test.py"
            meta_p = d / "meta.json"
            run_p = d / "run.json"
            if not test.exists() or test.stat().st_size == 0 or not meta_p.exists() or not run_p.exists():
                continue
            run = json.loads(run_p.read_text())
            if run.get("verdict") == "PROVEN":
                continue
            meta = json.loads(meta_p.read_text())
            if not meta.get("repo") or not meta.get("buggy_sha") or not meta.get("source_path"):
                continue
            rel = meta["source_path"]
            if not rel.endswith(".py"):
                continue
            rows.append(d)
    return rows


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else VANTAGE / "receipts/dev/vantage-code-fullrepo-b1-2026-08-23"
    (out / "OPEN").mkdir(parents=True, exist_ok=True)
    rows = []
    for case in iter_candidates():
        meta = json.loads((case / "meta.json").read_text())
        rel = meta["source_path"]
        sparse = rel.split("/")[0]
        module = module_from_source_path(rel)
        print(f"FULLREPO {case.name} {meta['repo']} {module}", flush=True)
        try:
            buggy = checkout(meta["repo"], meta["buggy_sha"], sparse)
            fixed = checkout(meta["repo"], meta["fixed_sha"], sparse)
            row = verify_repo(
                buggy_root=buggy,
                fixed_root=fixed,
                test_py=case / "repro_test.py",
                module=module,
            )
        except Exception as exc:
            row = {
                "verdict": "UNVERIFIED",
                "reason": f"{type(exc).__name__}:{exc}",
                "module": module,
            }
        row["case"] = case.name
        row["source_board"] = str(case.parent.parent.name)
        row["repo"] = meta["repo"]
        row["buggy_sha"] = meta["buggy_sha"]
        row["fixed_sha"] = meta["fixed_sha"]
        row.pop("rewritten_test", None)
        rows.append(row)
        print(json.dumps({"case": case.name, "verdict": row["verdict"], "reason": row.get("reason")}), flush=True)
    proven = sum(1 for r in rows if r.get("verdict") == "PROVEN")
    summary = {"n": len(rows), "proven": proven, "unverified": len(rows) - proven, "cases": rows}
    (out / "OPEN" / "SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"n": len(rows), "proven": proven}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
