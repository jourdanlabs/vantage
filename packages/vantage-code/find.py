#!/usr/bin/env python3
"""VANTAGE CODE finder — Kimi K3 proposes a candidate + a differential test.

The model is structurally forbidden from being the proof. Output is `dispatched`.
verify.py decides PROVEN / UNVERIFIED from a pytest run with no model.
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

MODEL = "kimi-k3"
API_URL = "https://api.moonshot.ai/v1/chat/completions"
KEYCHAIN_SERVICE = "bifrost.v1"
KEYCHAIN_ACCOUNT = "kimi"

SYSTEM = """You are the FIND lane of VANTAGE CODE. You propose correctness bugs. You are not the proof.

Given a Python unit (an extracted slice from a real OSS module) and its stated intent
(from the merge-commit / PR description of intended behavior), decide if the
implementation is wrong.

The unit is a SLICE. Names defined in the rest of the original module are absent.
If the slice uses a stdlib module (re, operator, collections, io, email, json, os)
without importing it, your test MAY bind it onto the imported module after import:
    import subject, re as _re
    subject.re = getattr(subject, "re", _re)
Do not install or import third-party packages (numpy, tensorflow, keras, pandas,
matplotlib, twisted, scrapy, thefuck). If the unit cannot be exercised without
those, set has_bug=false and leave test_py empty.

If you find a correctness bug, write a MINIMAL pytest that asserts the CORRECT
behavior from the stated intent (not "this is buggy"). The test must:
- import the unit from module `subject` (e.g. `from subject import format_sizeof`)
- contain at least one assert
- not import the file under review by any other name
- not sleep, network, or subprocess
- finish in under 2 seconds
- stay under 50 lines
- if the unit uses a `response` object, a tiny dummy with a `.headers` mapping is fine
- if the unit reads a directory, create it with tmp_path / tempfile inside the test

If the function matches the stated intent, set has_bug=false and leave test_py empty.

Reply with a single JSON object, no markdown, no commentary. Put test_py last.
Escape newlines inside test_py as \\n. Keep test_py short enough that the JSON
does not truncate.
{
  "has_bug": true,
  "location": "short location in the function",
  "claimed_wrong_behavior": "what it does vs what it should",
  "why": "one paragraph",
  "function_name": "the_function",
  "test_py": "full pytest source as a string"
}
"""


def keychain_secret(service: str, account: str) -> str:
    raw = subprocess.check_output(
        ["security", "find-generic-password", "-s", service, "-a", account, "-w"],
        stderr=subprocess.DEVNULL,
    )
    return raw.decode().strip()


def _strip_fences(text: str) -> str:
    cleaned = (text or "").strip()
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", cleaned).strip()
    # Unclosed think: drop through the last think opener if no closer.
    if "<think>" in cleaned and "</think>" not in cleaned:
        cleaned = cleaned.split("<think>", 1)[0].strip()
    cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.I)
    cleaned = re.sub(r"\s*```$", "", cleaned)
    return cleaned.strip()


def _first_json_object(text: str) -> str | None:
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_str = False
    esc = False
    for i, ch in enumerate(text[start:], start):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return text[start:]  # truncated object


def _salvage_truncated(blob: str) -> dict | None:
    """Close dangling strings / braces so a truncated object can still parse."""
    attempts = [
        blob,
        blob + '"',
        blob + '"}',
        blob + '"\n}',
        blob + '"]}',
        blob + "}",
        blob + "}}",
        blob.rstrip(",") + "}",
        blob.rstrip(",\n ") + "\n}",
    ]
    # Close N open braces.
    opens = blob.count("{") - blob.count("}")
    if opens > 0:
        attempts.append(blob + ('"' if blob.count('"') % 2 else "") + ("}" * opens))
    for cand in attempts:
        try:
            obj = json.loads(cand)
            if isinstance(obj, dict):
                return obj
        except json.JSONDecodeError:
            continue
        except ValueError:
            continue
    try:
        obj, _ = json.JSONDecoder().raw_decode(blob[blob.find("{") :])
        if isinstance(obj, dict):
            return obj
    except Exception:
        return None
    return None


def extract_json(text: str) -> dict:
    cleaned = _strip_fences(text)
    if not cleaned:
        raise json.JSONDecodeError("empty", cleaned, 0)
    try:
        obj = json.loads(cleaned)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        pass
    blob = _first_json_object(cleaned)
    if blob is None:
        # Last chance: a python fence meant as test_py with a JSON prefix elsewhere.
        raise json.JSONDecodeError("no JSON object", cleaned, 0)
    try:
        obj = json.loads(blob)
        if isinstance(obj, dict):
            return obj
    except json.JSONDecodeError:
        salvaged = _salvage_truncated(blob)
        if salvaged is not None:
            salvaged["_salvaged"] = True
            return salvaged
        raise
    raise json.JSONDecodeError("JSON was not an object", cleaned, 0)


def message_text(msg: dict) -> str:
    """Kimi/Moonshot thinking models park JSON in reasoning_content when content is empty."""
    parts = []
    for key in ("content", "reasoning_content", "reasoning"):
        val = msg.get(key)
        if isinstance(val, str) and val.strip():
            parts.append(val)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, dict) and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item, str):
                    parts.append(item)
    return "\n".join(parts).strip()


def test_py_compiles(src: str) -> str | None:
    if not src or not src.strip():
        return None
    try:
        ast.parse(src)
    except SyntaxError as exc:
        return f"SyntaxError:{exc.msg} line {exc.lineno}"
    if "assert" not in src:
        return "no_assert"
    if not re.search(r"from subject import |import subject", src):
        return "no_subject_import"
    return None


def _post(payload: dict, api_key: str) -> dict:
    req = urllib.request.Request(
        API_URL,
        data=json.dumps(payload).encode(),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.loads(resp.read().decode())


def find_one(case_dir: Path, api_key: str) -> dict:
    source = (case_dir / "buggy.py").read_text()
    spec = (case_dir / "spec.txt").read_text() if (case_dir / "spec.txt").exists() else ""
    user = (
        f"CASE: {case_dir.name}\n\n"
        f"STATED INTENT:\n{spec}\n\n"
        f"IMPLEMENTATION (this is the only code you see):\n```python\n{source}\n```\n"
        "Reply with the JSON object only. test_py must be a JSON string with escaped newlines.\n"
        "Put test_py last. Keep it under 50 lines so the JSON does not truncate.\n"
    )
    base_messages = [
        {"role": "system", "content": SYSTEM},
        {"role": "user", "content": user},
    ]
    last_err = "no_attempt"
    last_raw = ""
    body: dict = {}
    parsed = None
    for attempt in range(1, 5):
        messages = list(base_messages)
        if attempt == 2:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Your previous reply was empty or not valid JSON. "
                        "Return ONLY the JSON object. No markdown. No think tags. "
                        "Escape newlines in test_py. Keep test_py under 40 lines."
                    ),
                }
            )
        elif attempt >= 3:
            messages.append(
                {
                    "role": "user",
                    "content": (
                        f"Parse failed ({last_err}). Resend one JSON object. "
                        "If has_bug is true, include a short valid pytest in test_py. "
                        "If you cannot write a stdlib-only test, set has_bug=false "
                        "and test_py to an empty string."
                    ),
                }
            )
        payload = {
            "model": MODEL,
            "max_tokens": 16384,
            "messages": messages,
            "response_format": {"type": "json_object"},
        }
        # High reasoning on attempt 1; drop it if that produced empty content.
        if attempt == 1:
            payload["reasoning_effort"] = "low"
        try:
            body = _post(payload, api_key)
        except urllib.error.HTTPError as exc:
            err = exc.read().decode(errors="replace")[:800]
            last_err = f"http_{exc.code}"
            last_raw = err.replace(api_key, "[redacted]")
            if exc.code in (400, 422) and "response_format" in err:
                payload.pop("response_format", None)
                payload.pop("reasoning_effort", None)
                try:
                    body = _post(payload, api_key)
                except Exception as exc2:
                    last_err = f"{type(exc2).__name__}:{exc2}"
                    time.sleep(3 * attempt)
                    continue
            elif exc.code in (429, 503, 502):
                time.sleep(8 * attempt)
                continue
            else:
                time.sleep(2 * attempt)
                continue
        except Exception as exc:
            last_err = f"{type(exc).__name__}:{exc}"
            time.sleep(2 * attempt)
            continue
        msg = (body.get("choices") or [{}])[0].get("message") or {}
        content = message_text(msg)
        last_raw = content[-6000:]
        if not content.strip():
            last_err = "empty_content"
            time.sleep(1)
            continue
        try:
            parsed = extract_json(content)
        except (json.JSONDecodeError, ValueError) as exc:
            last_err = f"json_parse:{exc}"
            continue
        test_py = parsed.get("test_py") or ""
        if parsed.get("has_bug") and test_py:
            compile_err = test_py_compiles(test_py)
            if compile_err:
                last_err = f"test_py_{compile_err}"
                parsed = None
                continue
        break
    if parsed is None:
        dispatched = {
            "ok": False,
            "error": last_err,
            "raw": last_raw,
            "model": MODEL,
        }
        (case_dir / "dispatched.json").write_text(json.dumps(dispatched, indent=2) + "\n")
        return dispatched
    test_py = parsed.get("test_py") or ""
    if parsed.get("has_bug") and test_py:
        (case_dir / "repro_test.py").write_text(test_py if test_py.endswith("\n") else test_py + "\n")
    else:
        (case_dir / "repro_test.py").write_text("")
    dispatched = {
        "ok": True,
        "model": MODEL,
        "has_bug": bool(parsed.get("has_bug")),
        "location": parsed.get("location"),
        "claimed_wrong_behavior": parsed.get("claimed_wrong_behavior"),
        "why": parsed.get("why"),
        "function_name": parsed.get("function_name"),
        "test_bytes": len(test_py.encode()) if test_py else 0,
        "salvaged": bool(parsed.get("_salvaged")),
        "usage": body.get("usage"),
    }
    (case_dir / "dispatched.json").write_text(json.dumps(dispatched, indent=2, sort_keys=True) + "\n")
    return dispatched


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: find.py <case-dir> [<case-dir>...]")
        return 2
    api_key = os.environ.get("MOONSHOT_API_KEY") or keychain_secret(KEYCHAIN_SERVICE, KEYCHAIN_ACCOUNT)
    cases = [Path(arg) for arg in sys.argv[1:]]
    failed = 0

    def _run(case: Path) -> tuple[str, dict]:
        print(f"FIND {case.name} ...", flush=True)
        return case.name, find_one(case, api_key)

    from concurrent.futures import ThreadPoolExecutor, as_completed

    with ThreadPoolExecutor(max_workers=2) as pool:
        futs = [pool.submit(_run, case) for case in cases]
        for fut in as_completed(futs):
            name, row = fut.result()
            if not row.get("ok"):
                failed += 1
                print(json.dumps({"case": name, **{k: row[k] for k in row if k != "raw"}}, sort_keys=True))
            else:
                print(
                    json.dumps(
                        {
                            "case": name,
                            "has_bug": row["has_bug"],
                            "test_bytes": row["test_bytes"],
                            "location": row.get("location"),
                            "salvaged": row.get("salvaged"),
                        },
                        sort_keys=True,
                    ),
                    flush=True,
                )
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
