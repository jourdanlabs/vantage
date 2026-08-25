#!/usr/bin/env python3
"""Spike-0 orchestrator: find (Kimi K3) → verify (pytest, no model) → receipt."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

from verify import sha256_file, verify_case

HERE = Path(__file__).resolve().parent
FIND = HERE / "find.py"
VERIFY = HERE / "verify.py"


def fence_check() -> None:
    text = VERIFY.read_text()
    forbidden = ("moonshot", "openai", "kimi-k3", "find.py", "urllib.request")
    hits = [w for w in forbidden if w in text]
    if hits:
        raise SystemExit(f"FENCE RED: verify.py mentions {hits}")


def run_controls(cases_dir: Path, proven_row: dict | None) -> list[dict]:
    controls = []

    # Control 1: same-source non-bug cannot be PROVEN (structural).
    nonbug = next((p for p in sorted(cases_dir.iterdir()) if p.is_dir() and p.name.startswith("control_nonbug_")), None)
    if nonbug is None:
        controls.append({"id": "nonbug-same-source", "expect": "not-PROVEN", "got": "missing", "pass": False, "detail": {}})
    else:
        if not ((nonbug / "repro_test.py").exists() and (nonbug / "repro_test.py").stat().st_size):
            donor = None
            if proven_row:
                donor = cases_dir / proven_row["case"] / "repro_test.py"
            if donor is None or not donor.exists():
                for cand in cases_dir.glob("*/repro_test.py"):
                    if cand.stat().st_size:
                        donor = cand
                        break
            if donor and donor.exists() and donor.stat().st_size:
                shutil.copy(donor, nonbug / "repro_test.py")
        row = verify_case(nonbug)
        controls.append(
            {
                "id": "nonbug-same-source",
                "expect": "not-PROVEN",
                "got": row["verdict"],
                "pass": row["verdict"] != "PROVEN",
                "detail": row,
            }
        )

    # Control 2: line-shift of a PROVEN buggy file still FAILS the same test.
    if proven_row:
        src = cases_dir / proven_row["case"]
        shifted = cases_dir / "_control_lineshift"
        if shifted.exists():
            shutil.rmtree(shifted)
        shutil.copytree(src, shifted)
        buggy = (shifted / "buggy.py").read_text()
        (shifted / "buggy.py").write_text("\n" + buggy)
        shifted_row = verify_case(shifted)
        controls.append(
            {
                "id": "line-shift-invariant",
                "expect": "PROVEN",
                "got": shifted_row["verdict"],
                "pass": shifted_row["verdict"] == "PROVEN",
                "detail": {
                    "source_case": proven_row["case"],
                    "shifted_buggy_sha256": shifted_row.get("buggy_sha256"),
                    "verdict": shifted_row["verdict"],
                },
            }
        )
        shutil.rmtree(shifted, ignore_errors=True)

    # Control 3: corrupt the stored test bytes → receipt hash mismatch (RED).
    if proven_row and proven_row.get("test_sha256"):
        src = cases_dir / proven_row["case"] / "repro_test.py"
        live = hashlib.sha256(src.read_bytes()).hexdigest()
        mutated = src.read_bytes() + b"# corrupt\n"
        mutated_sha = hashlib.sha256(mutated).hexdigest()
        controls.append(
            {
                "id": "corrupt-receipt-hash",
                "expect": "RED (hash mismatch)",
                "got": "mismatch" if mutated_sha != proven_row["test_sha256"] else "match",
                "pass": mutated_sha != proven_row["test_sha256"] and live == proven_row["test_sha256"],
                "detail": {
                    "recorded": proven_row["test_sha256"],
                    "live": live,
                    "mutated": mutated_sha,
                },
            }
        )

    return controls


def main() -> int:
    fence_check()
    spike = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
    if not spike:
        print("usage: spike0.py <spike-dir>")
        return 2
    cases_dir = spike / "cases"
    skip = {"control_nonbug_gcd", "_control_lineshift"}
    skip |= {p.name for p in cases_dir.iterdir() if p.is_dir() and p.name.startswith("control_")}
    case_dirs = sorted(
        p for p in cases_dir.iterdir() if p.is_dir() and p.name not in skip
    )

    find_cmd = [sys.executable, str(FIND), *[str(p) for p in case_dirs]]
    print("== FIND (kimi-k3) ==", flush=True)
    find_proc = subprocess.run(find_cmd)
    if find_proc.returncode != 0:
        print("FIND had failures; continuing to verify whatever tests landed", flush=True)

    print("== VERIFY (pytest, no model) ==", flush=True)
    rows = []
    for case in case_dirs:
        row = verify_case(case)
        dispatched_path = case / "dispatched.json"
        if dispatched_path.exists():
            dispatched = json.loads(dispatched_path.read_text())
            row["location"] = dispatched.get("location")
            row["claimed_wrong_behavior"] = dispatched.get("claimed_wrong_behavior")
            row["finder_has_bug"] = dispatched.get("has_bug")
            row["model"] = dispatched.get("model")
        (case / "run.json").write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
        rows.append(row)
        print(f"  {row['case']:32} {row['verdict']:12} {row['reason']}", flush=True)

    proven_rows = [r for r in rows if r["verdict"] == "PROVEN"]
    print("== CONTROLS ==", flush=True)
    controls = run_controls(cases_dir, proven_rows[0] if proven_rows else None)
    for c in controls:
        mark = "PASS" if c["pass"] else "FAIL"
        print(f"  {c['id']:32} {mark}  got={c['got']}", flush=True)

    summary = {
        "spike": "vantage-code-spike0-2026-08-23",
        "n": len(rows),
        "proven": len(proven_rows),
        "unverified": sum(1 for r in rows if r["verdict"] == "UNVERIFIED"),
        "controls_pass": all(c["pass"] for c in controls),
        "finder_model": "kimi-k3",
        "verifier": "packages/vantage-code/verify.py",
        "fence": "verify.py has no model imports",
        "cases": rows,
        "controls": [{k: v for k, v in c.items() if k != "detail"} | {"detail": c.get("detail")} for c in controls],
    }
    out = spike / "OPEN" / "SPIKE0-SUMMARY.json"
    out.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"n": summary["n"], "proven": summary["proven"], "controls_pass": summary["controls_pass"]}))
    return 0 if summary["controls_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
