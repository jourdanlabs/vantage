"""
VantageAnalyzer — runs the VANTAGE X pipeline against a codebase path.

VANTAGE X is a Node.js tool. This wrapper locates the `vantage` binary and
invokes it via subprocess, capturing the JSON report output.

Usage:
    from vantage import analyze

    report = analyze("/path/to/project")
    print(report.verdict)       # APPROVED or REJECTED
    print(report.score_pct)     # e.g. "87.4%"
    for issue in report.aurora.top_issues:
        print(issue.severity, issue.file, issue.description)
"""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from .models import AuroraVerdict, Breakdown, Issue, VantageReport


def analyze(
    path: str,
    engine: Optional[str] = None,
    semantic: bool = False,
    vantage_bin: Optional[str] = None,
) -> VantageReport:
    """
    Run the VANTAGE X pipeline against ``path``.

    Args:
        path:        Absolute or relative path to the codebase to analyse.
        engine:      Run a single engine only: METEOR, NOVA, ECLIPSE, PULSAR,
                     NEBULA, or AURORA. Default runs the full pipeline.
        semantic:    If True, enables NEBULA semantic/taint analysis. Slower
                     (3–5× runtime) but finds cross-assignment taint flows
                     that pattern matchers cannot detect.
        vantage_bin: Path to the ``vantage`` binary. Auto-detected if omitted.

    Returns:
        VantageReport with verdict, score, issues, and full breakdown.

    Raises:
        FileNotFoundError: If the vantage binary cannot be located.
        RuntimeError:      If the pipeline fails.
    """
    analyzer = VantageAnalyzer(vantage_bin=vantage_bin)
    return analyzer.run(path, engine=engine, semantic=semantic)


class VantageAnalyzer:
    """
    Reusable analyzer instance.

    Args:
        vantage_bin: Explicit path to the ``vantage`` binary.
                     Auto-detected from PATH, then from common locations.
    """

    def __init__(self, vantage_bin: Optional[str] = None):
        self.vantage_bin = vantage_bin or _find_vantage_bin()

    def run(
        self,
        path: str,
        engine: Optional[str] = None,
        semantic: bool = False,
    ) -> VantageReport:
        abs_path = str(Path(path).resolve())
        if not Path(abs_path).exists():
            raise FileNotFoundError(f"Path not found: {abs_path}")

        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = os.path.join(tmpdir, "vantage-report.json")

            # Use `analyze` subcommand (not the deprecated `run`) and the
            # documented --semantic flag for NEBULA.
            cmd = [self.vantage_bin, "analyze", abs_path, "--output", report_path]
            if engine:
                cmd += ["--engine", engine.upper()]
            if semantic:
                cmd += ["--semantic"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=tmpdir,
            )

            if result.returncode != 0:
                raise RuntimeError(
                    f"VANTAGE pipeline failed:\n{result.stderr or result.stdout}"
                )

            if not os.path.exists(report_path):
                raise RuntimeError("VANTAGE did not produce a report file.")

            with open(report_path) as f:
                raw = json.load(f)

        return _parse_report(raw)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _find_vantage_bin() -> str:
    """
    Auto-detect the `vantage` Node binary. Search order:
      1. $VANTAGE_BIN env var (explicit override)
      2. $PATH (npm install -g)
      3. Local node_modules (npm install in cwd)
      4. nvm / volta / yarn / pnpm global prefix
      5. Common user install paths

    If none match, raise with install instructions.
    """
    # 1. Explicit env var
    env_bin = os.environ.get("VANTAGE_BIN")
    if env_bin and os.path.exists(env_bin):
        return env_bin

    # 2. PATH
    found = shutil.which("vantage")
    if found:
        return found

    # 3. node_modules/.bin in cwd and its parents (project-local install)
    cwd = Path.cwd()
    for candidate_dir in [cwd, *cwd.parents]:
        local_bin = candidate_dir / "node_modules" / ".bin" / "vantage"
        if local_bin.exists():
            return str(local_bin)
        if candidate_dir == candidate_dir.parent:
            break

    # 4. Common npm-global / nvm / yarn / pnpm / volta locations
    home = Path.home()
    candidates = [
        home / ".npm-global" / "bin" / "vantage",
        home / ".npm" / "bin" / "vantage",
        home / ".volta" / "bin" / "vantage",
        home / ".yarn" / "bin" / "vantage",
        home / ".local" / "share" / "pnpm" / "vantage",
        Path("/usr/local/bin/vantage"),
        Path("/opt/homebrew/bin/vantage"),
    ]
    # nvm puts binaries under ~/.nvm/versions/node/vX.Y.Z/bin — scan for any
    nvm_root = home / ".nvm" / "versions" / "node"
    if nvm_root.exists():
        for ver in sorted(nvm_root.iterdir(), reverse=True):
            candidate = ver / "bin" / "vantage"
            if candidate.exists():
                return str(candidate)

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)

    raise FileNotFoundError(
        "Could not locate the `vantage` binary.\n"
        "  Install:   npm install -g vantage\n"
        "  Or set:    export VANTAGE_BIN=/path/to/vantage\n"
        "  Or pass:   vantage_bin='/path/to/vantage' to analyze()"
    )


def _parse_report(raw: dict) -> VantageReport:
    aurora_raw = raw.get("aurora", {})
    breakdown_raw = aurora_raw.get("breakdown", {})

    breakdown = Breakdown(
        complexity_score=breakdown_raw.get("complexityScore", 0.0),
        dependency_score=breakdown_raw.get("dependencyScore", 0.0),
        risk_score=breakdown_raw.get("riskScore", 0.0),
        adversarial_score=breakdown_raw.get("adversarialScore", 0.0),
    )

    top_issues = [
        Issue(
            file=i.get("file", ""),
            severity=i.get("severity", "LOW"),
            description=i.get("description", ""),
            fix=i.get("fix"),
            line=i.get("line"),
        )
        for i in aurora_raw.get("topIssues", [])
    ]

    aurora = AuroraVerdict(
        verdict=aurora_raw.get("verdict", "REJECTED"),
        score=aurora_raw.get("score", 0.0),
        summary=aurora_raw.get("summary", ""),
        breakdown=breakdown,
        top_issues=top_issues,
    )

    meteor = raw.get("meteor", {})
    metrics = meteor.get("metrics", {})

    return VantageReport(
        verdict=aurora.verdict,
        score=aurora.score,
        aurora=aurora,
        file_count=len(meteor.get("files", [])),
        function_count=len(meteor.get("functions", [])),
        lines_of_code=metrics.get("linesOfCode", 0),
        todo_count=len(meteor.get("todos", [])),
        circular_dep_count=len(raw.get("nova", {}).get("circularDeps", [])),
        finding_count=len(raw.get("pulsar", {}).get("adversarialFindings", [])),
        raw=raw,
    )
