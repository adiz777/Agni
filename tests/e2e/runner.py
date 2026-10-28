"""Agni (अग्नि) E2E Test Suite Runner.

Dedicated CLI runner supporting tier selection, live/mock execution, and rich reporting.
Usage:
    python tests/e2e/runner.py
    python tests/e2e/runner.py --tier 1
    python tests/e2e/runner.py --tier 4 -v
    python tests/e2e/runner.py --url http://127.0.0.1:8000/api/v1
"""

from __future__ import annotations

import argparse
import os
import sys
import time
import unittest

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

BANNER = f"""{CYAN}{BOLD}
   __ _             _  (_)_ _ _ _ __ (_)
  / _` |/ _` | '_ \\| | | | | | '_ ` \\| |
 | (_| | (_| | | | | |_| | | | | | | | |
  \\__,_|\\__, |_| |_|\\__,_|_|_|_| |_| |_|
        |___/
{RESET}{YELLOW}[*] Agni (Agni) - Independent Opaque-Box E2E Testing Framework{RESET}
"""

TIER_MODULES = {
    1: ("Tier 1: Feature Coverage", "tests.e2e.test_tier1_feature_coverage"),
    2: ("Tier 2: Boundary & Corner Cases", "tests.e2e.test_tier2_boundary_corner_cases"),
    3: ("Tier 3: Cross-Feature Combinations", "tests.e2e.test_tier3_cross_feature_combinations"),
    4: ("Tier 4: Real-World Workload Scenarios", "tests.e2e.test_tier4_real_world_scenarios"),
}


class ColoredTestResult(unittest.TextTestResult):
    """Custom TestResult providing colored tier progress."""

    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.successes = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.successes.append(test)
        if self.showAll:
            self.stream.write(f"  {GREEN}[ PASS ]{RESET} {test.id().split('.')[-1]}\n")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        if self.showAll:
            self.stream.write(f"  {RED}[ FAIL ]{RESET} {test.id().split('.')[-1]}\n")

    def addError(self, test, err):
        super().addError(test, err)
        if self.showAll:
            self.stream.write(f"  {RED}[ ERR! ]{RESET} {test.id().split('.')[-1]}\n")


def run_tier(tier_num: int, tier_name: str, module_name: str, verbosity: int, filter_pattern: str | None) -> tuple[int, int, int, float]:
    """Load and execute all tests in a tier module."""
    print(f"\n{BOLD}{CYAN}[*] Running {tier_name}{RESET} ({module_name})")
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(module_name)

    if filter_pattern:
        filtered_tests = []
        for test in suite:
            if hasattr(test, "_tests"):
                for subtest in test:
                    if filter_pattern.lower() in subtest.id().lower():
                        filtered_tests.append(subtest)
            elif filter_pattern.lower() in test.id().lower():
                filtered_tests.append(test)
        suite = unittest.TestSuite(filtered_tests)

    start_time = time.time()
    runner = unittest.TextTestRunner(
        verbosity=verbosity,
        resultclass=ColoredTestResult,
        stream=sys.stdout,
    )
    result = runner.run(suite)
    elapsed = time.time() - start_time

    pass_count = len(getattr(result, "successes", []))
    fail_count = len(result.failures)
    err_count = len(result.errors)

    status_color = GREEN if (fail_count == 0 and err_count == 0) else RED
    status_text = "PASSED" if (fail_count == 0 and err_count == 0) else "FAILED"

    print(
        f"  {status_color}{BOLD}[+] {tier_name}: {status_text}{RESET} "
        f"({pass_count} passed, {fail_count} failed, {err_count} errors in {elapsed:.2f}s)"
    )

    return pass_count, fail_count, err_count, elapsed


def main() -> int:
    parser = argparse.ArgumentParser(description="Agni (अग्नि) E2E Test Suite Runner")
    parser.add_argument("--tier", type=int, choices=[1, 2, 3, 4], help="Run only specific tier (1, 2, 3, or 4)")
    parser.add_argument("--filter", type=str, help="Filter tests by name substring")
    parser.add_argument("--url", type=str, help="Target Agni REST API URL (e.g. http://127.0.0.1:8000/api/v1)")
    parser.add_argument("-v", "--verbose", action="store_true", default=True, help="Verbose test execution")
    args = parser.parse_args()

    if args.url:
        os.environ["AGNI_API_URL"] = args.url

    print(BANNER)
    target_url = os.environ.get("AGNI_API_URL", "Auto-Detect / Embedded Reference Server")
    print(f"Target Environment: {BOLD}{target_url}{RESET}")
    print(f"Working Directory : {os.getcwd()}")
    print("-" * 75)

    tiers_to_run = [args.tier] if args.tier else [1, 2, 3, 4]

    total_pass = 0
    total_fail = 0
    total_err = 0
    total_start = time.time()

    summary_rows = []

    for t_num in tiers_to_run:
        name, mod = TIER_MODULES[t_num]
        p, f, e, duration = run_tier(t_num, name, mod, verbosity=2 if args.verbose else 1, filter_pattern=args.filter)
        total_pass += p
        total_fail += f
        total_err += e
        summary_rows.append((name, p, f, e, duration))

    total_duration = time.time() - total_start

    print("\n" + "=" * 75)
    print(f"{BOLD}E2E TEST EXECUTION SUMMARY{RESET}")
    print("=" * 75)
    for name, p, f, e, dur in summary_rows:
        status_col = GREEN if (f == 0 and e == 0) else RED
        status_txt = "PASS" if (f == 0 and e == 0) else "FAIL"
        print(f" {status_col}[{status_txt}]{RESET} {name:<45} | {p:>2} passed, {f:>2} failed | {dur:5.2f}s")
    print("-" * 75)
    total_status = GREEN if (total_fail == 0 and total_err == 0) else RED
    result_word = "ALL TESTS PASSED" if (total_fail == 0 and total_err == 0) else "SOME TESTS FAILED"
    print(
        f"{total_status}{BOLD}Total: {total_pass} passed, {total_fail} failed, {total_err} errors across "
        f"{len(tiers_to_run)} tiers in {total_duration:.2f}s — {result_word}{RESET}\n"
    )

    return 0 if (total_fail == 0 and total_err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
