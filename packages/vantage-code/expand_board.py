#!/usr/bin/env python3
"""Expand the VANTAGE CODE board from BugsInPy — extractable units only.

Pull next bugs, extract the changed function(s), write spec from the merge
commit message. Finder never sees correct.py. Does not reopen scored cases.
"""
from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import textwrap
import urllib.error
import urllib.request
from pathlib import Path

BUGSINPY = Path("/tmp/BugsInPy/projects")
# Original 8-board + expand-b1. Never reopen scored keys.
SKIP_KEYS = {
    ("youtube-dl", "4"),
    ("youtube-dl", "5"),
    ("youtube-dl", "6"),
    ("youtube-dl", "21"),
    ("tqdm", "9"),
    ("scrapy", "14"),
    ("cookiecutter", "2"),
    ("httpie", "5"),
    # expand-b1
    ("PySnooper", "1"),
    ("black", "2"),
    ("black", "5"),
    ("scrapy", "30"),
    ("scrapy", "38"),
    ("thefuck", "9"),
    ("thefuck", "10"),
    ("thefuck", "13"),
    ("thefuck", "23"),
    ("tqdm", "2"),
    ("youtube-dl", "20"),
    ("youtube-dl", "22"),
    ("youtube-dl", "23"),
    ("youtube-dl", "24"),
    ("youtube-dl", "25"),
    ("youtube-dl", "27"),
    ("youtube-dl", "28"),
    ("youtube-dl", "31"),
    ("youtube-dl", "33"),
    ("youtube-dl", "34"),
    ("youtube-dl", "35"),
    ("youtube-dl", "41"),
}
# Overnight loop can add already-scored (project, bug_id) pairs without reopening them.
_extra_skip = os.environ.get("EXPAND_SKIP_JSON", "").strip()
if _extra_skip:
    for pair in json.loads(_extra_skip):
        SKIP_KEYS.add((str(pair[0]), str(pair[1])))

# Prefer projects whose units imported with stdlib last round.
# youtube-dl last: expand-b1 was 12/22 youtube-dl — diversify.
PREFER = [
    "thefuck",
    "scrapy",
    "cookiecutter",
    "httpie",
    "tqdm",
    "PySnooper",
    "black",
    "sanic",
    "fastapi",
    "keras",
    "pandas",
    "youtube-dl",
]

# Stdlib modules referenced as `re.sub` / `operator.eq` in extracted units.
STDLIB_ATTR = {
    "re", "os", "sys", "json", "operator", "datetime", "math", "collections",
    "itertools", "functools", "copy", "time", "struct", "base64", "hashlib",
    "html", "io", "pathlib", "typing", "enum", "abc", "contextlib", "warnings",
    "traceback", "inspect", "ast", "textwrap", "shutil", "tempfile",
    "subprocess", "urllib", "http", "csv", "decimal", "random", "string",
    "types", "dataclasses", "weakref", "locale", "calendar", "unicodedata",
    "errno", "stat", "glob", "fnmatch", "codecs", "binascii", "gzip", "zlib",
    "pickle", "shelve", "logging", "argparse", "shlex", "ntpath", "posixpath",
}
TYPING_NAMES = {
    "List": "from typing import List",
    "Dict": "from typing import Dict",
    "Optional": "from typing import Optional",
    "Tuple": "from typing import Tuple",
    "Set": "from typing import Set",
    "Any": "from typing import Any",
    "Iterable": "from typing import Iterable",
    "Union": "from typing import Union",
    "Callable": "from typing import Callable",
    "Sequence": "from typing import Sequence",
    "Mapping": "from typing import Mapping",
    "Type": "from typing import Type",
    "FrozenSet": "from typing import FrozenSet",
    "DefaultDict": "from typing import DefaultDict",
    "NamedTuple": "from typing import NamedTuple",
}
BARE_STDLIB = {
    "OrderedDict": "from collections import OrderedDict",
    "defaultdict": "from collections import defaultdict",
    "Counter": "from collections import Counter",
    "namedtuple": "from collections import namedtuple",
    "deque": "from collections import deque",
    "BufferedIOBase": "from io import BufferedIOBase",
    "RawIOBase": "from io import RawIOBase",
    "IOBase": "from io import IOBase",
    "BytesIO": "from io import BytesIO",
    "StringIO": "from io import StringIO",
    "TextIOBase": "from io import TextIOBase",
    "email": "import email",
    "Path": "from pathlib import Path",
    "PurePath": "from pathlib import PurePath",
    "datetime": "import datetime",
    "timedelta": "from datetime import timedelta",
    "partial": "from functools import partial",
    "reduce": "from functools import reduce",
    "lru_cache": "from functools import lru_cache",
    "wraps": "from functools import wraps",
    "deepcopy": "from copy import deepcopy",
    "urlparse": "from urllib.parse import urlparse",
    "urljoin": "from urllib.parse import urljoin",
    "quote": "from urllib.parse import quote",
    "unquote": "from urllib.parse import unquote",
    "parse_qs": "from urllib.parse import parse_qs",
    "urlencode": "from urllib.parse import urlencode",
    "urlopen": "from urllib.request import urlopen",
    "HTTPError": "from urllib.error import HTTPError",
    "URLError": "from urllib.error import URLError",
    "Request": "from urllib.request import Request",
    "MutableMapping": "from collections.abc import MutableMapping",
}


def prelude_for(unit: str) -> str:
    """Prepend stdlib/typing imports the sliced function uses. Seal-time only."""
    lines = []
    for mod in sorted(STDLIB_ATTR):
        if re.search(rf"\b{re.escape(mod)}\.", unit):
            lines.append(f"import {mod}")
    used = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", unit))
    for name, stmt in TYPING_NAMES.items():
        if name in used:
            lines.append(stmt)
    for name, stmt in BARE_STDLIB.items():
        if name in used:
            lines.append(stmt)
    if "maketrans" in used and "str.maketrans" not in unit:
        lines.append("maketrans = str.maketrans")
    seen: set[str] = set()
    out = []
    for line in lines:
        if line not in seen:
            seen.add(line)
            out.append(line)
    return ("\n".join(out) + "\n\n") if out else ""


def slice_func(text: str, name: str) -> str | None:
    m = re.search(rf"^([ \t]*)def {name}\(", text, re.M)
    if not m:
        return None
    indent = m.group(1)
    rest = text[m.start() :]
    m2 = re.search(rf"\n{re.escape(indent)}(?:def |class )", rest[1:])
    body = rest if not m2 else rest[: m2.start() + 1]
    return textwrap.dedent(body).strip() + "\n"


def slice_class(text: str, name: str) -> str | None:
    m = re.search(rf"^class {name}\b", text, re.M)
    if not m:
        return None
    lines = text[m.start() :].splitlines(True)
    buf = [lines[0]]
    for line in lines[1:]:
        if re.match(r"^(def |class |@)", line):
            break
        buf.append(line)
    return "".join(buf).strip() + "\n"


def github_repo(project_dir: Path) -> str | None:
    info = (project_dir / "project.info").read_text(errors="replace")
    m = re.search(r'github_url="https://github.com/([^"/]+/[^"/]+)', info)
    return m.group(1).rstrip("/") if m else None


def parse_bug_info(path: Path) -> dict:
    out = {}
    for line in path.read_text(errors="replace").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip()
    return out


def changed_funcs(patch: str) -> list[tuple[str, str]]:
    """Return [(relpath, funcname), ...] from hunk headers AND hunk bodies.

    BugsInPy hunks often say `@@ class Foo:` with the actual `def` only in the
    body. Header-only parsing dropped ~295 of 502 bugs (funcs_0).
    """
    file = None
    pairs: list[tuple[str, str]] = []
    scores: dict[tuple[str, str], int] = {}
    in_py = False
    current_hunk_defs: list[str] = []

    def add(path: str, name: str, weight: int = 1) -> None:
        key = (path, name)
        scores[key] = scores.get(key, 0) + weight
        pairs.append(key)

    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            file = line[6:]
            in_py = bool(file.endswith(".py") and "test" not in file.lower())
            continue
        if not in_py or not file:
            continue
        if line.startswith("@@"):
            current_hunk_defs = []
            m = re.search(r"def ([A-Za-z_][A-Za-z0-9_]*)", line)
            if m:
                add(file, m.group(1), 2)
                current_hunk_defs.append(m.group(1))
            continue
        mdef = re.match(r"^[+\- ]\s*def ([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
        if mdef:
            add(file, mdef.group(1), 3)
            current_hunk_defs.append(mdef.group(1))
            continue
        if line.startswith("+") or line.startswith("-"):
            if line.startswith("+++") or line.startswith("---"):
                continue
            if current_hunk_defs:
                add(file, current_hunk_defs[-1], 1)
            else:
                # attribute the line to a def named in this line if present
                m = re.search(r"def ([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
                if m:
                    add(file, m.group(1), 1)
    # unique preserve order, highest-score first per file
    ranked = sorted(scores.items(), key=lambda kv: (-kv[1], pairs.index(kv[0]) if kv[0] in pairs else 0))
    seen = set()
    uniq = []
    for key, _ in ranked:
        if key in seen:
            continue
        seen.add(key)
        uniq.append(key)
    return uniq


def patch_line_map(patch: str) -> dict[str, set[int]]:
    """Map file -> set of changed line numbers on the buggy side (@@ old start)."""
    file = None
    out: dict[str, set[int]] = {}
    old_ln = None
    for line in patch.splitlines():
        if line.startswith("+++ b/"):
            file = line[6:]
            continue
        if line.startswith("@@"):
            m = re.search(r"@@ -(\d+)", line)
            if m:
                old_ln = int(m.group(1))
            continue
        if file is None or old_ln is None:
            continue
        if line.startswith("-") and not line.startswith("---"):
            out.setdefault(file, set()).add(old_ln)
            old_ln += 1
        elif line.startswith("+") and not line.startswith("+++"):
            out.setdefault(file, set()).add(old_ln)
        elif line.startswith(" "):
            old_ln += 1
    return out


def enclosing_funcs(src: str, lines: set[int]) -> list[str]:
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return []
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            if any(node.lineno <= ln <= end for ln in lines):
                names.append(node.name)
    # unique preserve
    seen = set()
    uniq = []
    for n in names:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def gh_raw(repo: str, sha: str, path: str) -> str | None:
    url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, OSError):
        return None


GIT_CACHE = Path("/tmp/vantage-code-git")


FULL_CLONES = {
    "pandas-dev/pandas": Path("/tmp/vantage-pandas-full"),
    "keras-team/keras": Path("/tmp/vantage-keras-full"),
}


def git_show(repo: str, sha: str, path: str) -> str | None:
    """Fallback when GitHub raw 404s. Sparse-fetch one commit into a cache."""
    dest = FULL_CLONES.get(repo) or (GIT_CACHE / repo.replace("/", "_"))
    dest.mkdir(parents=True, exist_ok=True)
    if not (dest / ".git").exists():
        proc = subprocess.run(
            ["git", "init", "-q", str(dest)],
            capture_output=True,
            timeout=30,
        )
        if proc.returncode != 0:
            return None
        subprocess.run(
            ["git", "-C", str(dest), "remote", "add", "origin", f"https://github.com/{repo}.git"],
            capture_output=True,
            timeout=30,
        )
    fetch = subprocess.run(
        ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", sha],
        capture_output=True,
        timeout=90,
    )
    if fetch.returncode != 0:
        return None
    show = subprocess.run(
        ["git", "-C", str(dest), "show", f"{sha}:{path}"],
        capture_output=True,
        timeout=20,
    )
    if show.returncode != 0:
        return None
    return show.stdout.decode("utf-8", errors="replace")


def commit_message(repo: str, sha: str) -> str:
    try:
        raw = subprocess.check_output(
            ["gh", "api", f"repos/{repo}/commits/{sha}", "--jq", ".commit.message"],
            stderr=subprocess.DEVNULL,
            timeout=20,
        )
        return raw.decode().strip()
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return ""


def compiles(src: str) -> bool:
    try:
        ast.parse(src)
        return True
    except SyntaxError:
        return False


def write_case(root: Path, cid: str, meta: dict, spec: str, buggy: str, correct: str) -> None:
    d = root / cid
    d.mkdir(parents=True, exist_ok=True)
    (d / "meta.json").write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")
    (d / "spec.txt").write_text(spec.strip() + "\n")
    (d / "buggy.py").write_text(buggy if buggy.endswith("\n") else buggy + "\n")
    (d / "correct.py").write_text(correct if correct.endswith("\n") else correct + "\n")
    (d / "SOURCE.md").write_text(
        f"# Source\n\n- repo: {meta['repo']}\n"
        f"- buggy_commit: {meta['buggy_sha']}\n"
        f"- fixed_commit: {meta['fixed_sha']}\n"
        f"- extracted_unit: {meta['extracted_unit']}\n"
        "- note: extracted unit; finder sees buggy.py + spec.txt only.\n"
    )


def candidates() -> list[tuple[str, str, Path]]:
    rows = []
    order = PREFER + [p.name for p in sorted(BUGSINPY.iterdir()) if p.name not in PREFER]
    seen_proj = set()
    for name in order:
        if name in seen_proj:
            continue
        seen_proj.add(name)
        proj = BUGSINPY / name
        bugs = proj / "bugs"
        if not bugs.is_dir():
            continue
        for b in sorted(bugs.iterdir(), key=lambda p: int(p.name) if p.name.isdigit() else 0):
            if (name, b.name) in SKIP_KEYS:
                continue
            patch_p = b / "bug_patch.txt"
            info_p = b / "bug.info"
            if not patch_p.exists() or not info_p.exists():
                continue
            patch = patch_p.read_text(errors="replace")
            nlines = len(patch.splitlines())
            if not (4 <= nlines <= 800):
                continue
            funcs = changed_funcs(patch)
            if not funcs:
                continue
            # Dominant file (most ranked defs). Skip if that file is tests.
            by_file: dict[str, list[str]] = {}
            for f, fn2 in funcs:
                by_file.setdefault(f, []).append(fn2)
            rel = max(by_file, key=lambda f: len(by_file[f]))
            if "test" in rel.lower() or not rel.endswith(".py"):
                continue
            fn = by_file[rel][0]
            if rel.count("/") > 8:
                continue
            rows.append((name, b.name, b, rel, fn))
    return rows


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--limit", type=int, default=22)
    ap.add_argument("--max-per-project", type=int, default=12)
    ap.add_argument("--batch", default="toph-b1")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    written = 0
    skipped = 0
    per_project: dict[str, int] = {}
    for proj, bid, bdir, rel, fn in candidates():
        if written >= args.limit:
            break
        if per_project.get(proj, 0) >= args.max_per_project:
            skipped += 1
            continue
        info = parse_bug_info(bdir / "bug.info")
        repo = github_repo(bdir.parent.parent)
        buggy_sha = info.get("buggy_commit_id", "").replace(" ", "")
        fixed_sha = info.get("fixed_commit_id", "").replace(" ", "")
        if not repo or not buggy_sha or not fixed_sha:
            skipped += 1
            continue
        src_b = gh_raw(repo, buggy_sha, rel) or git_show(repo, buggy_sha, rel)
        src_f = gh_raw(repo, fixed_sha, rel) or git_show(repo, fixed_sha, rel)
        if not src_b or not src_f:
            skipped += 1
            continue
        # Try ranked funcs until the two slices actually differ. funcs[0] is
        # often an unchanged neighbor in the same hunk (same-unit skip).
        patch = (bdir / "bug_patch.txt").read_text(errors="replace")
        ranked = changed_funcs(patch)
        line_map = patch_line_map(patch)
        extra = enclosing_funcs(src_b, line_map.get(rel, set()))
        try_names = []
        for rel2, fn2 in ranked:
            if rel2 == rel and fn2 not in try_names:
                try_names.append(fn2)
        for n in extra:
            if n not in try_names:
                try_names.append(n)
        if fn not in try_names:
            try_names.append(fn)
        unit_b = unit_f = None
        picked = fn
        for fn2 in try_names:
            ub = slice_func(src_b, fn2) or slice_class(src_b, fn2)
            uf = slice_func(src_f, fn2) or slice_class(src_f, fn2)
            if ub and uf and ub != uf:
                unit_b, unit_f, picked = ub, uf, fn2
                break
        if not unit_b or not unit_f:
            skipped += 1
            continue
        unit_b = prelude_for(unit_b) + unit_b
        unit_f = prelude_for(unit_f) + unit_f
        if not compiles(unit_b) or not compiles(unit_f):
            skipped += 1
            continue
        if len(unit_b) > 12000 or len(unit_f) > 12000:
            skipped += 1
            continue
        msg = commit_message(repo, fixed_sha)
        if not msg:
            msg = f"Fix {picked} in {rel} ({proj} bug {bid})."
        # Don't leak the patch into spec. Commit message is intent.
        spec = (
            msg.split("\n\ndiff")[0].strip()
            + f"\n\nStated intent: `{picked}` in `{rel}` must implement the behavior described above."
        )
        cid = f"{proj}-{bid}-{picked}".replace("_", "-")
        # filesystem-safe
        cid = re.sub(r"[^a-zA-Z0-9.-]", "-", cid)[:80]
        if (out / cid).exists():
            skipped += 1
            continue
        meta = {
            "repo": repo,
            "buggy_sha": buggy_sha,
            "fixed_sha": fixed_sha,
            "extracted_unit": picked,
            "source_path": rel,
            "bugs_in_py": f"{proj}/{bid}",
            "batch": args.batch,
        }
        write_case(out, cid, meta, spec, unit_b, unit_f)
        written += 1
        per_project[proj] = per_project.get(proj, 0) + 1
        print(f"WROTE {written}/{args.limit} {cid} ({len(unit_b)}/{len(unit_f)} bytes)", flush=True)
    if written:
        write_control_nonbug(out)
    print(json.dumps({"written": written, "skipped": skipped, "per_project": per_project}))
    return 0 if written else 1


def write_control_nonbug(out: Path) -> None:
    """Same-source control so airlock has a donor. Not a scored case."""
    donors = sorted(
        p
        for p in out.iterdir()
        if p.is_dir() and not p.name.startswith("control_") and not p.name.startswith("_")
    )
    if not donors:
        return
    donor = donors[0]
    dest = out / f"control_nonbug_{donor.name[:32]}"
    if dest.exists():
        return
    dest.mkdir(parents=True, exist_ok=True)
    src = (donor / "buggy.py").read_text()
    (dest / "buggy.py").write_text(src)
    (dest / "correct.py").write_text(src)
    (dest / "spec.txt").write_text("CONTROL: same-source non-bug. Must never score PROVEN.\n")
    (dest / "SOURCE.md").write_text("# CONTROL nonbug — same source both sides. Not a scored case.\n")
    (dest / "meta.json").write_text(
        json.dumps({"control": "nonbug-same-source", "donor": donor.name}, indent=2) + "\n"
    )
    print(f"WROTE control {dest.name}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
