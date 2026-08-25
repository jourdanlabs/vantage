#!/usr/bin/env python3
"""When Macroscope login completes, review PROVEN buggy-vs-fixed diffs.

Does not stamp CLEAR. Writes OPEN/macroscope/. Polls up to 20 minutes.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent.parent / "receipts/dev/vantage-code-toph-2026-08-24/OPEN/macroscope"
BIN = Path.home() / ".local/bin/macroscope"
# HEAD = buggy snapshot; --base = fixed SHA so the diff is the defect.
JOBS = [
    {
        "id": "ytdl-23-js-to-json",
        "cwd": "/tmp/vantage-code-co/ytdl-org_youtube-dl/a22b2fd19bd8",
        "base": "b3ee552e4b918fb720111b23147e24fa5475a74b",
        "note": "extracted+fullrepo PROVEN js_to_json; 4-line utils.py diff",
    },
    {
        "id": "httpie-2-get-response",
        "cwd": "/tmp/vantage-code-co/jakubroztocil_httpie/356e0436510f",
        "base": "e18b609ef7d867d6efa0efe42c832be5e0d09338",
        "note": "fullrepo PROVEN get_response",
    },
]


def utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def me() -> dict:
    proc = subprocess.run([str(BIN), "me"], capture_output=True, text=True, timeout=30)
    try:
        return json.loads(proc.stdout or proc.stderr or "{}")
    except json.JSONDecodeError:
        return {"success": False, "raw": (proc.stdout or "")[-500]}


def review(job: dict) -> dict:
    cwd = Path(job["cwd"])
    dest = OUT / job["id"]
    dest.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["PATH"] = str(BIN.parent) + os.pathsep + env.get("PATH", "")
    cmd = [str(BIN), "codereview", "--base", job["base"], "--raw", "--in-place"]
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=300,
        env=env,
    )
    (dest / "stdout.txt").write_text(proc.stdout or "")
    (dest / "stderr.txt").write_text(proc.stderr or "")
    issues = []
    combined = (proc.stderr or "") + "\n" + (proc.stdout or "")
    for line in combined.splitlines():
        if line.startswith("issue_event="):
            try:
                issues.append(json.loads(line[len("issue_event=") :]))
            except json.JSONDecodeError:
                issues.append({"raw": line[:500]})
    row = {
        "id": job["id"],
        "ts": utc(),
        "cmd": cmd,
        "cwd": job["cwd"],
        "base": job["base"],
        "note": job["note"],
        "returncode": proc.returncode,
        "n_issues": len(issues),
        "issues": issues[:50],
    }
    (dest / "SUMMARY.json").write_text(json.dumps(row, indent=2, sort_keys=True) + "\n")
    return row


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    deadline = time.time() + 20 * 60
    while time.time() < deadline:
        status = me()
        (OUT / "me.json").write_text(json.dumps(status, indent=2) + "\n")
        if status.get("success"):
            rows = []
            for job in JOBS:
                if not Path(job["cwd"]).exists():
                    rows.append({"id": job["id"], "skipped": "cwd missing"})
                    continue
                print(utc(), "REVIEW", job["id"], flush=True)
                try:
                    rows.append(review(job))
                except Exception as exc:
                    rows.append({"id": job["id"], "error": "%s:%s" % (type(exc).__name__, exc)})
            (OUT / "BATCH.json").write_text(
                json.dumps({"ts": utc(), "user": status, "rows": rows}, indent=2) + "\n"
            )
            print(utc(), "done", json.dumps({"n": len(rows)}), flush=True)
            return 0
        time.sleep(15)
    (OUT / "TIMEOUT.json").write_text(
        json.dumps({"ts": utc(), "reason": "login not completed in 20m"}, indent=2) + "\n"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
