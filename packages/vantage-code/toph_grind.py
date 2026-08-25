#!/usr/bin/env python3
"""Toph lane: seal-before-find → Kimi find → pytest verify on a FRESH board.

Does not write overnight/expand-b* seals. Never CLEAR. Budget-aware.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from airlock_batch import airlock, utc  # noqa: E402
from overnight_loop import (  # noqa: E402
    CAP_TOTAL,
    BIFROST_SPENT,
    case_dirs,
    find_one,
    is_scored,
    merge_run,
    remaining_budget,
    seal_board,
    vantage_find_spent,
)
from verify import verify_case  # noqa: E402

VANTAGE = HERE.parent.parent
BOARD = VANTAGE / "receipts/dev/vantage-code-board-toph-b1-2026-08-24"
LOG = VANTAGE / "receipts/dev/vantage-code-toph-2026-08-24"
PAN = Path("/Users/sokpyeon/projects/pan-cc/handoffs")
TOPH_FIND_CAP = 120  # of the 278 remaining; leave headroom


def log(msg: str) -> None:
    line = f"{utc()} {msg}"
    print(line, flush=True)
    LOG.mkdir(parents=True, exist_ok=True)
    with (LOG / "grind.log").open("a") as fh:
        fh.write(line + "\n")


def toph_spent() -> int:
    n = 0
    if not (BOARD / "cases").is_dir():
        return 0
    for d in case_dirs(BOARD):
        if (d / "dispatched.json").exists():
            n += 1
    return n


def main() -> int:
    LOG.mkdir(parents=True, exist_ok=True)
    if not case_dirs(BOARD):
        log(f"no cases on {BOARD} — expand first")
        return 2
    digest = seal_board(BOARD)
    log(f"SEAL sha256={digest}")
    scored = []
    for case in case_dirs(BOARD):
        if is_scored(case):
            scored.append(json.loads((case / "run.json").read_text()))
            continue
        if remaining_budget() <= 0 or toph_spent() >= TOPH_FIND_CAP:
            log(f"budget stop remaining={remaining_budget()} toph_spent={toph_spent()}")
            break
        log(f"FIND {case.name} remaining={remaining_budget()} toph={toph_spent()}/{TOPH_FIND_CAP}")
        find_one(case)
        row = merge_run(case, verify_case(case))
        scored.append(row)
        log(f"SCORED {case.name} {row['verdict']} {row.get('reason')}")
        (LOG / "PROGRESS.json").write_text(
            json.dumps(
                {
                    "ts": utc(),
                    "board": str(BOARD),
                    "proven": sum(1 for r in scored if r.get("verdict") == "PROVEN"),
                    "n": len(scored),
                    "toph_spent": toph_spent(),
                    "global_spent": BIFROST_SPENT + vantage_find_spent(),
                    "cap": CAP_TOTAL,
                },
                indent=2,
            )
            + "\n"
        )
    air = airlock(BOARD)
    log(f"AIRLOCK {air['result']}")
    proven = [r for r in scored if r.get("verdict") == "PROVEN"]
    uv = [r for r in scored if r.get("verdict") != "PROVEN"]
    packet = PAN / "HOLD-NOT-FOR-PAN-VANTAGE-CODE-TOPH-B1-2026-08-24"
    packet.mkdir(parents=True, exist_ok=True)
    (packet / "HOLD.md").write_text(
        "# HOLD — not for Pan — VANTAGE CODE toph-b1 · "
        + utc()
        + "\n\n"
        "**readyForGate:** false until crush bar. Scores stay SEPARATE from 8-board/b1/b2.\n"
        f"n={len(scored)} PROVEN={len(proven)} UNVERIFIED={len(uv)} "
        f"airlock={air['result']} toph_spent={toph_spent()} "
        f"global={BIFROST_SPENT + vantage_find_spent()}/{CAP_TOTAL}\n"
        f"PROVEN ids: {', '.join(r['case'] for r in proven) or '(none yet)'}\n"
        "Extracted caveat rides. UNVERIFIED is not a bug. README untouched. Not self-CLEAR.\n"
    )
    log(f"HOLD {packet} proven={len(proven)}/{len(scored)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
