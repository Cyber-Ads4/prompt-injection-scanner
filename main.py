"""
main.py — Entry point for the LLM Prompt Injection Scanner

Usage:
    python main.py --target claude --output reports/results.html

What this does:
    Orchestrates the full scan pipeline: load payloads → run scan → score results → generate report
"""

import argparse
import os
import sys
from scanner.runner import ScanRunner
from scanner.payloads import PayloadLibrary
from reports.report_gen import ReportGenerator


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for the scanner."""
    parser = argparse.ArgumentParser(
        description="LLM Prompt Injection Scanner — AI Security Portfolio Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python main.py --target claude --output reports/results.html
    python main.py --target claude --category role_hijack --verbose
        """
    )
    parser.add_argument(
        "--target",
        choices=["claude"],
        default="claude",
        help="Which LLM API to test (default: claude)"
    )
    parser.add_argument(
        "--category",
        default="all",
        help="Payload category to test: all, role_hijack, jailbreak, data_exfil, prompt_leak (default: all)"
    )
    parser.add_argument(
        "--output",
        default="reports/results.html",
        help="Output path for HTML report (default: reports/results.html)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print each payload and response to terminal as they run"
    )
    return parser.parse_args()


def check_environment() -> None:
    """
    Verify required environment variables are set before running.
    Security note: We never hardcode API keys — always pull from environment.
    """
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[ERROR] ANTHROPIC_API_KEY environment variable not set.")
        print("Set it with: export ANTHROPIC_API_KEY='your-key-here'")
        sys.exit(1)


def main() -> None:
    """Main orchestration function — runs the full scan pipeline."""
    args = parse_args()
    check_environment()

    print(f"\n🔍 LLM Prompt Injection Scanner")
    print(f"   Target : {args.target}")
    print(f"   Category: {args.category}")
    print(f"   Output  : {args.output}\n")

    # Step 1: Load payloads
    library = PayloadLibrary()
    payloads = library.get_payloads(category=args.category)
    print(f"[+] Loaded {len(payloads)} payloads from library\n")

    # Step 2: Run scan
    runner = ScanRunner(verbose=args.verbose)
    results = runner.run(payloads=payloads)
    print(f"\n[+] Scan complete — {len(results)} results collected")

    # Step 3: Generate report
    reporter = ReportGenerator()
    reporter.generate(results=results, output_path=args.output)
    print(f"[+] Report saved to: {args.output}\n")


if __name__ == "__main__":
    main()
