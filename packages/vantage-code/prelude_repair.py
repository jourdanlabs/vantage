#!/usr/bin/env python3
"""New-board extract repair: apply stdlib prelude, re-run EXISTING tests.

Does not mutate sealed boards. Does not call FIND. Does not reopen old verdicts.
Old UNVERIFIED rows stay UNVERIFIED on their original board.
"""
from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from expand_board import prelude_for, write_control_nonbug  # noqa: E402
from overnight_loop import case_dirs, merge_run, seal_board  # noqa: E402
from verify import verify_case  # noqa: E402
from airlock_batch import airlock, utc  # noqa: E402

VANTAGE = HERE.parent.parent
ROOT = VANTAGE / "receipts/dev"
OUT = VANTAGE / "receipts/dev/vantage-code-board-toph-prelude-2026-08-24"

STDLIB_NAMES = {
    "re", "operator", "OrderedDict", "List", "Dict", "Optional", "Tuple", "Set",
    "Any", "email", "BufferedIOBase", "maketrans", "Path", "datetime", "deepcopy",
    "partial", "Counter", "defaultdict", "deque", "MutableMapping", "BytesIO",
    "StringIO", "IOBase", "RawIOBase",
}


def donor_cases() -> list[Path]:
    rows = []
    for board in sorted(ROOT.glob("vantage-code-board*")):
        if "toph-prelude" in board.name:
            continue
        cases = board / "cases"
        if not cases.is_dir():
            continue
        for d in sorted(cases.iterdir()):
            if not d.is_dir() or d.name.startswith("control") or d.name.startswith("_"):
                continue
            runp, test = d / "run.json", d / "repro_test.py"
            if not runp.exists() or not test.exists() or test.stat().st_size == 0:
                continue
            run = json.loads(runp.read_text())
            if run.get("verdict") == "PROVEN":
                continue
            tail = (run.get("buggy_tail") or "") + (run.get("fixed_tail") or "")
            m = re.search(r"NameError: name '([^']+)'", tail)
            if not m or m.group(1) not in STDLIB_NAMES:
                continue
            rows.append(d)
    return rows


def strip_old_prelude(src: str) -> str:
    """Drop leading import/from/maketrans= lines so prelude_for is idempotent."""
    lines = src.splitlines(True)
    i = 0
    while i < len(lines):
        s = lines[i].strip()
        if s == "" and i < 8:
            i += 1
            continue
        if s.startswith("import ") or s.startswith("from ") or s.startswith("maketrans ="):
            i += 1
            continue
        break
    return "".join(lines[i:])


def copy_repaired(src: Path, dest_root: Path) -> Path:
    dest = dest_root / src.name
    dest.mkdir(parents=True, exist_ok=True)
    for name in ("SOURCE.md", "meta.json", "spec.txt", "repro_test.py"):
        shutil.copy2(src / name, dest / name)
    meta = json.loads((dest / "meta.json").read_text())
    meta["prelude_repair"] = True
    meta["repaired_from"] = src.parent.parent.name
    (dest / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    for side in ("buggy.py", "correct.py"):
        raw = strip_old_prelude((src / side).read_text())
        (dest / side).write_text(prelude_for(raw) + raw if not raw.endswith("\n") else prelude_for(raw) + raw)
        text = (dest / side).read_text()
        if not text.endswith("\n"):
            (dest / side).write_text(text + "\n")
    note = (dest / "SOURCE.md").read_text()
    (dest / "SOURCE.md").write_text(
        note + "\n- prelude_repair: stdlib imports applied at seal; existing finder test reused; no FIND.\n"
    )
    return dest


def main() -> int:
    out_cases = OUT / "cases"
    if out_cases.exists():
        shutil.rmtree(out_cases)
    out_cases.mkdir(parents=True, exist_ok=True)
    donors = donor_cases()
    print(f"donors {len(donors)}", flush=True)
    for src in donors:
        copy_repaired(src, out_cases)
        print(f"COPIED {src.name} from {src.parent.parent.name}", flush=True)
    write_control_nonbug(out_cases)
    digest = seal_board(OUT)
    print(f"SEAL {digest}", flush=True)
    rows = []
    for case in case_dirs(OUT):
        row = merge_run(case, verify_case(case))
        # finder fields: reuse original dispatched location if present on donor
        rows.append(row)
        print(f"{utc()} SCORED {row['case']} {row['verdict']} {row.get('reason')}", flush=True)
    proven = [r for r in rows if r.get("verdict") == "PROVEN"]
    air = airlock(OUT)
    summary = {
        "n": len(rows),
        "proven": len(proven),
        "ids": [r["case"] for r in proven],
        "airlock": air["result"],
        "seal": digest,
        "no_find": True,
        "existing_tests": True,
        "old_boards_unmutated": True,
    }
    (OUT / "REPAIR.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps(summary))
    print("AIRLOCK", air["result"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
