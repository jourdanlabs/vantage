#!/usr/bin/env python3
"""Overnight VANTAGE CODE grind — expand → seal-before-find → find blind → verify.

Guards: budget cap, stall-skip, never reopen scored cases, never CLEAR.
Does not start a second finder on an in-flight find.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from airlock_batch import SEAL_NAMES, airlock, utc  # noqa: E402
from verify import verify_case  # noqa: E402

VANTAGE = HERE.parent.parent
ORIG = VANTAGE / "receipts/dev/vantage-code-board-2026-08-23"
B1 = VANTAGE / "receipts/dev/vantage-code-board-expand-b1-2026-08-23"
NIGHT = VANTAGE / "receipts/dev/vantage-code-overnight-2026-08-23"
PAN = Path("/Users/sokpyeon/projects/pan-cc/handoffs")
FIND = HERE / "find.py"
EXPAND = HERE / "expand_board.py"

CAP_TOTAL = 400
BIFROST_SPENT = 15
TARGET_PROVEN = 30
FIND_TIMEOUT_S = 720  # find.py retries 3× at 180s
EXPAND_LIMIT = 40
BATCH_CEILING = 80


def now() -> str:
    return utc()


def log(msg: str) -> None:
    line = f"{now()} {msg}"
    print(line, flush=True)
    NIGHT.mkdir(parents=True, exist_ok=True)
    with (NIGHT / "overnight.log").open("a") as fh:
        fh.write(line + "\n")


def case_dirs(board: Path) -> list[Path]:
    cases = board / "cases"
    if not cases.is_dir():
        return []
    return sorted(
        p
        for p in cases.iterdir()
        if p.is_dir() and not p.name.startswith("control_") and not p.name.startswith("_control")
    )


def orig_counts() -> dict:
    proven = unverified = 0
    for d in case_dirs(ORIG):
        run = d / "run.json"
        if not run.exists():
            continue
        v = json.loads(run.read_text()).get("verdict")
        if v == "PROVEN":
            proven += 1
        elif v == "UNVERIFIED":
            unverified += 1
    return {"proven": proven, "unverified": unverified, "n": proven + unverified}


def expand_boards() -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    patterns = (
        "receipts/dev/vantage-code-board-expand-b*-2026-08-23",
        "receipts/dev/vantage-code-board-toph-*-2026-08-24",
    )
    for pat in patterns:
        for p in sorted(VANTAGE.glob(pat)):
            rp = p.resolve()
            if rp in seen or not p.is_dir():
                continue
            seen.add(rp)
            out.append(p)
    return out


def vantage_find_spent() -> int:
    n = 0
    for board in expand_boards():
        for d in case_dirs(board):
            if (d / "dispatched.json").exists():
                n += 1
    return n


def remaining_budget() -> int:
    return max(0, CAP_TOTAL - BIFROST_SPENT - vantage_find_spent())


def write_progress(extra: str = "") -> None:
    oc = orig_counts()
    b1_rows = []
    for d in case_dirs(B1):
        run = d / "run.json"
        if run.exists():
            b1_rows.append(json.loads(run.read_text()))
    later = []
    for board in expand_boards():
        if board.resolve() == B1.resolve():
            continue
        for d in case_dirs(board):
            run = d / "run.json"
            if run.exists():
                later.append(json.loads(run.read_text()))
    new_proven = sum(1 for r in b1_rows + later if r.get("verdict") == "PROVEN")
    new_uv = sum(1 for r in b1_rows + later if r.get("verdict") == "UNVERIFIED")
    total_proven = oc["proven"] + new_proven
    spent = BIFROST_SPENT + vantage_find_spent()
    line = (
        f"{now()} · orig {oc['proven']}/8 PROVEN · new_scored {len(b1_rows)+len(later)} "
        f"· new_PROVEN {new_proven} · new_UNVERIFIED {new_uv} · total_PROVEN {total_proven} "
        f"· budget {spent}/{CAP_TOTAL} · remaining {remaining_budget()}"
        + (f" · {extra}" if extra else "")
    )
    NIGHT.mkdir(parents=True, exist_ok=True)
    path = NIGHT / "PROGRESS.md"
    prev = path.read_text() if path.exists() else (
        "# PROGRESS — LOOP A VANTAGE CODE · overnight 2026-08-23/24\n\n"
        "Builder: Tifa · Finder: kimi-k3 · Verifier: verify.py (no model) · Airlock: mechanical · Gate: Pan\n\n"
        "Original gated board **5/8 PROVEN** stays sealed. UNVERIFIED is not reopened.\n\n"
        "| ts (UTC) | marker |\n|---|---|\n"
    )
    if not prev.endswith("\n"):
        prev += "\n"
    if line not in prev:
        prev += f"| {now()} | {line.split(' · ', 1)[-1] if ' · ' in line else line} |\n"
        path.write_text(prev)
    pan = PAN / "PROGRESS-VANTAGE-CODE.md"
    try:
        pan.write_text(path.read_text())
    except OSError as exc:
        log(f"WARN could not copy progress to pan-cc: {exc}")
    (NIGHT / "PROGRESS.json").write_text(
        json.dumps(
            {
                "ts": now(),
                "orig_proven": oc["proven"],
                "new_proven": new_proven,
                "new_unverified": new_uv,
                "total_proven": total_proven,
                "budget_spent": spent,
                "budget_cap": CAP_TOTAL,
                "remaining": remaining_budget(),
                "extra": extra,
            },
            indent=2,
        )
        + "\n"
    )
    log(line)


def inflight_find_pids() -> list[str]:
    proc = subprocess.run(["pgrep", "-f", "vantage-code/find.py"], capture_output=True, text=True)
    pids = [p for p in (proc.stdout or "").split() if p and p != str(os.getpid())]
    return pids


def wait_inflight_find(timeout_s: int = 5400) -> None:
    start = time.time()
    while True:
        pids = inflight_find_pids()
        if not pids:
            log("in-flight find.py: none")
            return
        if time.time() - start > timeout_s:
            log(f"STALL in-flight find.py pids={pids} > {timeout_s}s — continue with whatever landed")
            return
        log(f"wait find.py pids={pids}")
        time.sleep(20)


def is_scored(case: Path) -> bool:
    """Scored = find landed (dispatched.json) AND verify wrote run.json.

    A run.json with no dispatched.json is a premature verify, not a sealed UNVERIFIED.
    """
    return (case / "run.json").exists() and (case / "dispatched.json").exists()


def merge_run(case: Path, row: dict) -> dict:
    dispatched_path = case / "dispatched.json"
    if dispatched_path.exists():
        dispatched = json.loads(dispatched_path.read_text())
        row["location"] = dispatched.get("location")
        row["claimed_wrong_behavior"] = dispatched.get("claimed_wrong_behavior")
        row["finder_has_bug"] = dispatched.get("has_bug")
        row["model"] = dispatched.get("model")
        row["finder_ok"] = dispatched.get("ok")
        if dispatched.get("error"):
            row["finder_error"] = dispatched.get("error")
    (case / "run.json").write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
    return row


def verify_board(board: Path) -> list[dict]:
    rows = []
    for case in case_dirs(board):
        if is_scored(case):
            row = json.loads((case / "run.json").read_text())
            rows.append(row)
            continue
        row = merge_run(case, verify_case(case))
        rows.append(row)
        log(f"VERIFY {board.name} {row['case']} {row['verdict']} {row['reason']}")
        write_progress(f"verified {row['case']}={row['verdict']}")
    return rows


def find_one(case: Path) -> dict:
    if remaining_budget() <= 0:
        log("BUDGET CAP — stop find")
        return {"ok": False, "error": "budget_cap"}
    if is_scored(case):
        return json.loads((case / "run.json").read_text())
    if (case / "dispatched.json").exists():
        return json.loads((case / "dispatched.json").read_text())
    log(f"FIND {case.name} remaining={remaining_budget()}")
    try:
        proc = subprocess.run(
            [sys.executable, str(FIND), str(case)],
            cwd=str(HERE),
            capture_output=True,
            text=True,
            timeout=FIND_TIMEOUT_S,
        )
        if proc.returncode != 0:
            log(f"FIND-FAIL {case.name} rc={proc.returncode} {(proc.stderr or proc.stdout)[-300:]}")
    except subprocess.TimeoutExpired:
        log(f"STALL FIND timeout {case.name} — skip UNVERIFIED")
        (case / "dispatched.json").write_text(
            json.dumps({"ok": False, "error": "timeout", "model": "kimi-k3"}, indent=2) + "\n"
        )
    if (case / "dispatched.json").exists():
        return json.loads((case / "dispatched.json").read_text())
    return {"ok": False, "error": "no_dispatched"}


def existing_skip_keys() -> list[list[str]]:
    keys = []
    for board in (ORIG, *expand_boards()):
        for d in case_dirs(board):
            meta_p = d / "meta.json"
            if not meta_p.exists():
                continue
            meta = json.loads(meta_p.read_text())
            bip = str(meta.get("bugs_in_py") or "")
            if "/" in bip:
                proj, bid = bip.split("/", 1)
                keys.append([proj, bid])
    return keys


def seal_board(board: Path) -> str:
    lines = []
    for case in sorted((board / "cases").iterdir()) if (board / "cases").is_dir() else []:
        if not case.is_dir():
            continue
        for name in SEAL_NAMES:
            p = case / name
            if not p.exists():
                continue
            rel = f"cases/{case.name}/{name}"
            lines.append(f"{sha256_bytes(p.read_bytes())}  {rel}")
    text = "\n".join(lines) + ("\n" if lines else "")
    (board / "FILELIST").write_text(text)
    digest = hashlib.sha256(text.encode()).hexdigest()
    (board / "FILELIST.sha256").write_text(f"{digest}  FILELIST\n")
    (board / "RECEIPT.md").write_text(
        f"# SEAL — {board.name}\n\nSealed: {now()}\nFinder has not run.\nFILELIST.sha256:\n```\n{digest}  FILELIST\n```\n"
    )
    log(f"SEAL {board.name} sha256={digest}")
    return digest


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def total_proven() -> int:
    return orig_counts()["proven"] + sum(
        1
        for board in expand_boards()
        for d in case_dirs(board)
        if (d / "run.json").exists() and json.loads((d / "run.json").read_text()).get("verdict") == "PROVEN"
    )


def next_batch_i() -> int:
    n = 2
    for p in expand_boards():
        if not case_dirs(p):
            continue  # empty shells (b12…) must not consume the counter
        try:
            part = p.name.split("expand-b")[1].split("-")[0]
            n = max(n, int(part) + 1)
        except (IndexError, ValueError):
            continue
    return n


def board_fully_scored(board: Path) -> bool:
    dirs = case_dirs(board)
    return bool(dirs) and all(is_scored(d) for d in dirs)


def expand_next(batch_name: str) -> Path | None:
    out = VANTAGE / f"receipts/dev/vantage-code-board-{batch_name}-2026-08-23"
    if out.exists() and case_dirs(out):
        return out
    out.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["EXPAND_SKIP_JSON"] = json.dumps(existing_skip_keys())
    log(f"EXPAND {batch_name} skip={len(existing_skip_keys())} → {out}")
    proc = subprocess.run(
        [sys.executable, str(EXPAND), "--out", str(out / "cases"), "--limit", str(EXPAND_LIMIT)],
        cwd=str(HERE),
        env=env,
        capture_output=True,
        text=True,
        timeout=1800,
    )
    tail = (proc.stdout or "")[-1500:]
    log(f"EXPAND rc={proc.returncode} {tail}")
    if not case_dirs(out):
        log(f"EXPAND wrote 0 cases for {batch_name}")
        return None
    seal_board(out)
    return out


def write_blocked(text: str) -> None:
    NIGHT.mkdir(parents=True, exist_ok=True)
    (NIGHT / "BLOCKED.md").write_text(text if text.endswith("\n") else text + "\n")
    try:
        (PAN / "BLOCKED-VANTAGE-CODE.md").write_text((NIGHT / "BLOCKED.md").read_text())
    except OSError:
        pass


def write_b1_packet(rows: list[dict], air: dict) -> None:
    dest = PAN / "HOLD-NOT-FOR-PAN-VANTAGE-CODE-EXPAND-B1-2026-08-23"
    dest.mkdir(parents=True, exist_ok=True)
    proven = sum(1 for r in rows if r.get("verdict") == "PROVEN")
    (dest / "HOLD.md").write_text(
        "# HOLD — expand-b1 is not for Pan\n\n"
        "**readyForGate:** false. 1/22 is not crushing incumbents. Airlock loop continues.\n"
        f"airlock={air.get('result')} n={len(rows)} proven={proven}\n"
    )
    log(f"HOLD packet {dest}")


def grind_board(board: Path) -> list[dict]:
    for case in case_dirs(board):
        if is_scored(case):
            continue
        if remaining_budget() <= 0:
            log("BUDGET CAP — stop grind")
            break
        try:
            find_one(case)
        except Exception as exc:
            log(f"STALL {case.name} {type(exc).__name__}:{exc} — skip")
            (case / "dispatched.json").write_text(
                json.dumps({"ok": False, "error": f"{type(exc).__name__}", "model": "kimi-k3"}, indent=2) + "\n"
            )
        row = merge_run(case, verify_case(case))
        log(f"SCORED {case.name} {row['verdict']}")
        write_progress(f"{board.name} {case.name}={row['verdict']}")
    return verify_board(board)


def main() -> int:
    NIGHT.mkdir(parents=True, exist_ok=True)
    stop = NIGHT / "STOP"
    if stop.exists():
        log(f"STOP file present ({stop}) — halt without expanding")
        return 0
    write_blocked(
        "# BLOCKED — LOOP A VANTAGE CODE · overnight 2026-08-23/24\n\n"
        "- **CodeQL CLI:** `codeql` is not on PATH this session. SARIF files exist under "
        "expand-b1 `OPEN/codeql/` (driver CodeQL 2.26.3 from an earlier run) — that is not a "
        "re-runnable vs-CodeQL sentence tonight. Empty `semgrep-*.json` is not a fake 0.\n"
        "- **Rung 2 (full-repo):** not started. Rung 1 must hum first.\n"
        "- Original 8-unit UNVERIFIED (tqdm-format-sizeof, httpie-keyvalue-escape, "
        "ytdl-unified-timestamp) **not reopened**.\n"
        "- Keys: `bifrost.v1` kimi live (HTTP 200). minimax live (HTTP 200, unused on find.py).\n"
        "- BugsInPy corpus: `/tmp/BugsInPy/projects` present.\n"
    )
    write_progress("overnight_loop start")
    wait_inflight_find()
    if board_fully_scored(B1):
        log("expand-b1 already scored — skip reopen")
    else:
        log("verify expand-b1 (no reopen)")
        rows = grind_board(B1)
        air = airlock(B1)
        log(f"AIRLOCK b1 {air['result']}")
        write_b1_packet(rows, air)

    batch_i = next_batch_i()
    log(f"resume at expand-b{batch_i} proven={total_proven()} remaining={remaining_budget()}")
    empty_expands = 0
    while total_proven() < TARGET_PROVEN and remaining_budget() > 0:
        name = f"expand-b{batch_i}"
        board = expand_next(name)
        if board is None:
            empty_expands += 1
            log(f"EXPAND 0 at {name} empty={empty_expands} — sleep 60s and retry")
            time.sleep(60)
            if empty_expands >= 8:
                log("expand exhausted 8× — halt this process (wrapper may restart)")
                break
            batch_i += 1
            if batch_i > BATCH_CEILING:
                break
            continue
        empty_expands = 0
        if board_fully_scored(board):
            log(f"skip already scored {name}")
            batch_i += 1
            continue
        wait_inflight_find(timeout_s=2400)
        grind_board(board)
        air_n = airlock(board)
        log(f"AIRLOCK {name} {air_n['result']}")
        write_progress(f"{name} airlock={air_n['result']} proven_now={total_proven()}")
        dest = PAN / f"HOLD-NOT-FOR-PAN-VANTAGE-CODE-{name.upper()}-2026-08-23"
        dest.mkdir(parents=True, exist_ok=True)
        scored = [json.loads((d / "run.json").read_text()) for d in case_dirs(board) if (d / "run.json").exists()]
        proven_n = sum(1 for r in scored if r.get("verdict") == "PROVEN")
        (dest / "HOLD.md").write_text(
            f"# HOLD — not for Pan — VANTAGE CODE {name} · {now()}\n\n"
            f"**readyForGate:** false. Captain: Pan only gets the packet when we crush incumbents.\n"
            f"n={len(scored)} PROVEN={proven_n} UNVERIFIED={len(scored)-proven_n} "
            f"total_PROVEN={total_proven()} airlock={air_n['result']} budget={BIFROST_SPENT + vantage_find_spent()}/{CAP_TOTAL}\n"
            f"Crush bar: ≥{TARGET_PROVEN} PROVEN + rivals actually-run matched table + airlock PASS. Not there.\n"
        )
        batch_i += 1
        if batch_i > BATCH_CEILING:
            log(f"batch ceiling {BATCH_CEILING} — stop")
            break

    write_progress(f"overnight_loop halt total_PROVEN={total_proven()} remaining={remaining_budget()}")
    log("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
