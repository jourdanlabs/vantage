"""vantage-py CLI"""

import argparse
import sys

from .analyzer import VantageAnalyzer, _find_vantage_bin


def main():
    parser = argparse.ArgumentParser(
        prog="vantage-py",
        description="VANTAGE X — Static code analysis pipeline",
    )
    parser.add_argument("path", help="Path to the codebase to analyse")
    parser.add_argument("--engine", metavar="ENGINE",
                        help="Run single engine: METEOR, NOVA, ECLIPSE, PULSAR, NEBULA, AURORA")
    parser.add_argument("--semantic", action="store_true",
                        help="Enable NEBULA semantic/taint analysis (3-5x slower, catches cross-flow bugs)")
    parser.add_argument("--vantage-bin", metavar="PATH",
                        help="Path to vantage binary (auto-detected if omitted)")
    parser.add_argument("--json", action="store_true",
                        help="Print raw JSON report to stdout")
    args = parser.parse_args()

    try:
        analyzer = VantageAnalyzer(vantage_bin=args.vantage_bin)
        report = analyzer.run(args.path, engine=args.engine, semantic=args.semantic)
    except (FileNotFoundError, RuntimeError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.json:
        import json
        print(json.dumps(report.raw, indent=2))
        return

    verdict_sym = "✓" if report.approved else "✗"
    print(f"\nVANTAGE X\n")
    print(f"  {verdict_sym}  {report.verdict}  {report.score_pct}")
    print(f"\n  {report.aurora.summary}\n")
    print(f"  Complexity   {report.aurora.breakdown.complexity_score * 100:.0f}%")
    print(f"  Dependency   {report.aurora.breakdown.dependency_score * 100:.0f}%")
    print(f"  Risk         {report.aurora.breakdown.risk_score * 100:.0f}%")
    print(f"  Adversarial  {report.aurora.breakdown.adversarial_score * 100:.0f}%")

    if report.aurora.top_issues:
        print(f"\n  Top Issues:")
        for issue in report.aurora.top_issues[:5]:
            print(f"    [{issue.severity}] {issue.file}")
            print(f"           {issue.description}")

    print(f"\n  {report.file_count} files · {report.lines_of_code:,} LOC · "
          f"{report.finding_count} findings · {report.circular_dep_count} circ deps\n")
