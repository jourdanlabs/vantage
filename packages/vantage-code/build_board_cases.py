#!/usr/bin/env python3
"""Finish remaining board cases. Finder never sees correct.py."""
from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

ROOT = Path("/Users/sokpyeon/projects/vantage-recert-2026-08-02/vantage/receipts/dev/vantage-code-board-2026-08-23/cases")
TMP = Path("/tmp/vantage-code-realpr")


def slice_func(text: str, name: str) -> str:
    m = re.search(rf"^def {name}\(", text, re.M)
    if not m:
        raise SystemExit(f"missing {name}")
    rest = text[m.start() :]
    m2 = re.search(r"\n(?:def |class )", rest[1:])
    body = rest if not m2 else rest[: m2.start() + 1]
    return body.strip() + "\n"


def write_case(cid: str, meta: dict, spec: str, buggy: str, correct: str) -> None:
    d = ROOT / cid
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
        f"- note: unit extracted so pytest can run without the full project. "
        f"Finder sees buggy.py + spec.txt only.\n"
    )
    print("wrote", cid)


def gh_raw(repo: str, sha: str, path: str, dest: Path) -> None:
    url = f"https://raw.githubusercontent.com/{repo}/{sha}/{path}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=30) as resp:
        dest.write_bytes(resp.read())


def main() -> None:
    # scrapy is_gzipped — fix correct.py
    gz_f = TMP.joinpath("gz.fixed.py").read_text()
    # keep the regex helper that lives above the function
    m = re.search(r"^_is_gzipped_re = .*\n", gz_f, re.M)
    helper = m.group(0) if m else ""
    write_case(
        "scrapy-is-gzipped",
        {
            "repo": "scrapy/scrapy",
            "buggy_sha": "b7553d921afe356ec858bb1d2e5b1702df05ea24",
            "fixed_sha": "d43a35735a062a4260b002cfbcd3236c77ef9399",
            "extracted_unit": "is_gzipped",
            "bugs_in_py": "scrapy/14",
        },
        "Is_gzipped for application/x-gzip;charset=utf-8\n\n"
        "Stated intent: is_gzipped must treat a Content-Type that starts with "
        "application/gzip or application/x-gzip as gzipped even when parameters "
        "such as charset=utf-8 are present. response.headers is a mapping; "
        "Content-Type values may be bytes.",
        slice_func(TMP.joinpath("gz.buggy.py").read_text(), "is_gzipped"),
        "import re\n\n" + helper + "\n" + slice_func(gz_f, "is_gzipped"),
    )

    # youtube-dl unified_timestamp cluster
    u_b = TMP.joinpath("utils5.buggy.py").read_text()
    u_f = TMP.joinpath("utils5.fixed.py").read_text()

    def date_cluster(text: str) -> str:
        m = re.search(r"^DATE_FORMATS = \(", text, re.M)
        n = re.search(r"^def preferredencoding\(", text, re.M)
        constants = text[m.start() : n.start()]
        return (
            "import calendar\nimport datetime\nimport email.utils\nimport re\n\n"
            + constants
            + slice_func(text, "extract_timezone")
            + "\n"
            + slice_func(text, "date_formats")
            + "\n"
            + slice_func(text, "unified_timestamp")
        )

    write_case(
        "ytdl-unified-timestamp",
        {
            "repo": "ytdl-org/youtube-dl",
            "buggy_sha": "b02b960c6bba834d9e7199ac53430c7933079dc8",
            "fixed_sha": "7dc2a74e0ac9cfa74cc9de6f586ffd5cc8bac0d9",
            "extracted_unit": "DATE_FORMATS + extract_timezone + date_formats + unified_timestamp",
            "bugs_in_py": "youtube-dl/5",
        },
        "[utils] Fix unified_timestamp for formats parsed by parsedate_tz()\n\n"
        "Stated intent: unified_timestamp must parse AM/PM and timezone-bearing date "
        "strings, including formats that fall through to email.utils.parsedate_tz, "
        "and return a UNIX timestamp. PM times are 12 hours after the 12-hour clock value.",
        date_cluster(u_b),
        date_cluster(u_f),
    )

    # youtube-dl parse_dfxp_time_expr
    d_b = TMP.joinpath("utils6.buggy.py").read_text()
    d_f = TMP.joinpath("utils6.fixed.py").read_text()
    write_case(
        "ytdl-parse-dfxp-time",
        {
            "repo": "ytdl-org/youtube-dl",
            "buggy_sha": "4f29fa99069760dc47ef9ca5dbf607a567d2982f",
            "fixed_sha": "d631d5f9f27f93767226192e4288990413fa9dbd",
            "extracted_unit": "parse_dfxp_time_expr (core of TTML conversion fix)",
            "bugs_in_py": "youtube-dl/6",
        },
        "[utils] Fix TTML conversion\n\n"
        "Tolerate invalid timestamps (closes #7909)\n\n"
        "Stated intent: parse_dfxp_time_expr must tolerate a missing/empty timestamp "
        "by returning a missing value (not 0.0), so callers can skip invalid cues "
        "instead of treating them as t=0.",
        "import re\n\n" + slice_func(d_b, "parse_dfxp_time_expr"),
        "import re\n\n" + slice_func(d_f, "parse_dfxp_time_expr"),
    )

    # youtube-dl urljoin
    bsha = "96182695e4e37795a30ab143129c91dab18a9865"
    fsha = "4b5de77bdb7765df4797bf068592926285ba709a"
    gh_raw("ytdl-org/youtube-dl", bsha, "youtube_dl/utils.py", TMP / "utils21.buggy.py")
    gh_raw("ytdl-org/youtube-dl", fsha, "youtube_dl/utils.py", TMP / "utils21.fixed.py")
    j_b = (TMP / "utils21.buggy.py").read_text(errors="replace")
    j_f = (TMP / "utils21.fixed.py").read_text(errors="replace")
    head = (
        "import re\n"
        "from urllib.parse import urljoin as _urljoin\n"
        "compat_str = str\n\n"
        "def compat_urlparse_urljoin(base, path):\n"
        "    return _urljoin(base, path)\n\n"
    )

    def patch_urljoin(src: str) -> str:
        body = slice_func(src, "urljoin")
        return body.replace("compat_urlparse.urljoin", "compat_urlparse_urljoin")

    write_case(
        "ytdl-urljoin",
        {
            "repo": "ytdl-org/youtube-dl",
            "buggy_sha": bsha,
            "fixed_sha": fsha,
            "extracted_unit": "urljoin (compat_str=str, urllib.parse.urljoin shim)",
            "bugs_in_py": "youtube-dl/21",
        },
        "Stated intent: urljoin(base, path) must accept bytes or str for either argument, "
        "decode bytes as UTF-8, and return a joined URL. A path that is already absolute "
        "(http(s):// or //) is returned as-is. Empty or non-string paths return None.",
        head + patch_urljoin(j_b),
        head + patch_urljoin(j_f),
    )


if __name__ == "__main__":
    main()
