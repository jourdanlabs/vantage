#!/usr/bin/env python3
"""Mechanical airlock for a VANTAGE CODE board batch. Never CLEAR.

Checks: FILELIST live rehash · finder-blind · verifier-fence · controls.
Writes AIRLOCK.json next to the board. Exit 0 on AIRLOCK-PASS, 1 on FAIL.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from verify import sha256_file, verify_case  # noqa: E402


SEAL_NAMES = ("SOURCE.md", "buggy.py", "correct.py", "meta.json", "spec.txt")


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def live_rehash(board: Path) -> dict:
    fl = board / "FILELIST"
    stamp = board / "FILELIST.sha256"
    if not fl.exists() or not stamp.exists():
        return {"ok": False, "reason": "missing FILELIST"}
    recorded_filelist_sha = stamp.read_text().split()[0]
    live_filelist_sha = hashlib.sha256(fl.read_bytes()).hexdigest()
    mismatches = []
    for line in fl.read_text().splitlines():
        if not line.strip():
            continue
        rec_sha, rel = line.split(None, 1)
        path = board / rel
        if not path.exists():
            mismatches.append({"rel": rel, "reason": "missing"})
            continue
        live = sha256_file(path)
        if live != rec_sha:
            mismatches.append({"rel": rel, "recorded": rec_sha, "live": live})
    return {
        "ok": recorded_filelist_sha == live_filelist_sha and not mismatches,
        "filelist_sha_match": recorded_filelist_sha == live_filelist_sha,
        "recorded_filelist_sha": recorded_filelist_sha,
        "live_filelist_sha": live_filelist_sha,
        "mismatches": mismatches[:12],
        "n_mismatch": len(mismatches),
    }


def finder_blind() -> dict:
    text = (HERE / "find.py").read_text()
    opens_correct = "correct.py" in text
    reads_buggy = 'case_dir / "buggy.py"' in text or "buggy.py" in text
    reads_spec = "spec.txt" in text
    return {
        "ok": (not opens_correct) and reads_buggy and reads_spec,
        "opens_correct_py": opens_correct,
        "reads_buggy": reads_buggy,
        "reads_spec": reads_spec,
    }


def verifier_fence() -> dict:
    text = (HERE / "verify.py").read_text()
    forbidden = [w for w in ("moonshot", "openai", "kimi-k3", "find.py", "urllib.request") if w in text]
    return {"ok": not forbidden, "hits": forbidden}


def run_controls(board: Path) -> dict:
    cases = board / "cases"
    proven = []
    for d in sorted(p for p in cases.iterdir() if p.is_dir() and not p.name.startswith("control_")):
        run = d / "run.json"
        if not run.exists():
            continue
        row = json.loads(run.read_text())
        if row.get("verdict") == "PROVEN":
            proven.append(d)
    checks = []

    nonbug = next((p for p in cases.iterdir() if p.is_dir() and p.name.startswith("control_nonbug")), None)
    if nonbug is None:
        checks.append({"id": "nonbug-same-source", "pass": False, "got": "missing"})
    else:
        donor = None
        for p in proven:
            t = p / "repro_test.py"
            if t.exists() and t.stat().st_size:
                donor = t
                break
        if donor and not ((nonbug / "repro_test.py").exists() and (nonbug / "repro_test.py").stat().st_size):
            shutil.copy(donor, nonbug / "repro_test.py")
        row = verify_case(nonbug)
        checks.append(
            {
                "id": "nonbug-same-source",
                "pass": row["verdict"] != "PROVEN",
                "got": row["verdict"],
            }
        )

    if proven:
        src = proven[0]
        shifted = cases / "_control_lineshift"
        if shifted.exists():
            shutil.rmtree(shifted)
        shutil.copytree(src, shifted)
        (shifted / "buggy.py").write_text("\n" + (shifted / "buggy.py").read_text())
        row = verify_case(shifted)
        checks.append(
            {
                "id": "line-shift-invariant",
                "pass": row["verdict"] == "PROVEN",
                "got": row["verdict"],
                "source": src.name,
            }
        )
        shutil.rmtree(shifted, ignore_errors=True)
        test = src / "repro_test.py"
        live = hashlib.sha256(test.read_bytes()).hexdigest()
        recorded = json.loads((src / "run.json").read_text()).get("test_sha256")
        mutated = hashlib.sha256(test.read_bytes() + b"# corrupt\n").hexdigest()
        checks.append(
            {
                "id": "corrupt-receipt-hash",
                "pass": bool(recorded) and live == recorded and mutated != recorded,
                "got": "mismatch" if mutated != recorded else "match",
            }
        )
    else:
        checks.append({"id": "line-shift-invariant", "pass": False, "got": "no PROVEN to shift"})
        checks.append({"id": "corrupt-receipt-hash", "pass": False, "got": "no PROVEN"})

    return {"ok": all(c["pass"] for c in checks), "checks": checks}


def airlock(board: Path) -> dict:
    rehash = live_rehash(board)
    blind = finder_blind()
    fence = verifier_fence()
    controls = run_controls(board)
    checks = [
        {"id": "seal-rehash", "ok": rehash["ok"], "detail": {k: rehash[k] for k in rehash if k != "mismatches"}},
        {"id": "finder-blind", "ok": blind["ok"], "detail": blind},
        {"id": "verifier-fence", "ok": fence["ok"], "detail": fence},
        {"id": "controls", "ok": controls["ok"], "detail": controls["checks"]},
    ]
    all_ok = all(c["ok"] for c in checks)
    packet = {
        "kind": "AIRLOCK",
        "product": "VANTAGE-CODE",
        "ts": utc(),
        "board": str(board),
        "result": "AIRLOCK-PASS" if all_ok else "AIRLOCK-FAIL",
        "verdict": "never CLEAR — Pan gates the batch",
        "mechanical_only": True,
        "self_clear": False,
        "checks": checks,
    }
    dest = board / "AIRLOCK.json"
    dest.write_text(json.dumps(packet, indent=2, sort_keys=True) + "\n")
    return packet


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: airlock_batch.py <board-dir>")
        return 2
    packet = airlock(Path(sys.argv[1]).resolve())
    print(json.dumps({"dest": packet["board"] + "/AIRLOCK.json", "result": packet["result"]}, indent=2))
    return 0 if packet["result"] == "AIRLOCK-PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
