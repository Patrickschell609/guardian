#!/usr/bin/env python3
"""
GUARDIAN CLI - Autonomous Cross-Family Threat Hunting

Usage:
    guardian scan <path>       One-shot scan of a package/directory
    guardian scan pypi:<name>  Download from PyPI and scan (no install)
    guardian watch             Continuous PyPI + watchdog monitoring
    guardian demo              Run relay on a known-bad sample
    guardian stats             Show vault statistics
"""

import argparse
import json
import sys
import os

# Ensure the parent directory is in path for relative imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def main():
    parser = argparse.ArgumentParser(
        prog="guardian",
        description="GUARDIAN - Autonomous Cross-Family Threat Hunting",
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan a package or directory")
    scan_parser.add_argument("path", help="Path to scan, or pypi:<package> for PyPI")
    scan_parser.add_argument("--json", action="store_true", help="JSON output")
    scan_parser.add_argument("--quiet", "-q", action="store_true", help="Minimal output")
    mode_group = scan_parser.add_mutually_exclusive_group()
    mode_group.add_argument("--cheap", action="store_true",
                            help="Single-model analysis only (skip relay and evaluator)")
    mode_group.add_argument("--fast", action="store_true",
                            help="Shortened 3-stage relay, skip evaluator")

    # watch
    watch_parser = subparsers.add_parser("watch", help="Continuous monitoring")
    watch_parser.add_argument("--json", action="store_true", help="JSON output")

    # demo
    demo_parser = subparsers.add_parser("demo", help="Run demo with known-bad sample")
    demo_parser.add_argument("--json", action="store_true", help="JSON output")

    # stats
    stats_parser = subparsers.add_parser("stats", help="Show vault statistics")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print("\nExamples:")
        print("  guardian scan /path/to/package")
        print("  guardian scan pypi:some-package")
        print("  guardian watch")
        print("  guardian demo")
        print("  guardian stats")
        sys.exit(1)

    # Load .env if present
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    from guardian.guardian import run_scan, run_watch, run_demo
    from guardian.vault import get_vault_stats

    if args.command == "scan":
        verbose = not getattr(args, 'quiet', False)
        result = run_scan(args.path, verbose=verbose,
                          cheap=getattr(args, 'cheap', False),
                          fast=getattr(args, 'fast', False))
        if getattr(args, 'json', False):
            print(json.dumps(result, indent=2, default=str))
        elif not verbose:
            verdict = result.get("verdict", "?")
            score = result.get("score", 0)
            print(f"{verdict} ({score}/10)")
        # Exit code based on verdict
        if result.get("verdict") == "THREAT":
            sys.exit(2)
        elif result.get("verdict") == "CLEAN":
            sys.exit(0)
        else:
            sys.exit(1)

    elif args.command == "watch":
        result = run_watch(verbose=True)
        if getattr(args, 'json', False):
            print(json.dumps(result, indent=2, default=str))

    elif args.command == "demo":
        result = run_demo(verbose=True)
        if getattr(args, 'json', False):
            print(json.dumps(result, indent=2, default=str))

    elif args.command == "stats":
        stats = get_vault_stats()
        print(f"\n  GUARDIAN VAULT STATISTICS")
        print(f"  {'='*40}")
        print(f"  Total solutions: {stats['total_solutions']}")
        print(f"  Average score:   {stats['avg_score']}/10")
        print(f"  Total retrievals: {stats['total_retrievals']}")


if __name__ == "__main__":
    main()
