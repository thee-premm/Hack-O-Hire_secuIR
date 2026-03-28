"""
Run all model verification tests.
Run: cd backend && python tests/run_model_tests.py
"""

import subprocess
import sys
import os
import time

_TESTS = os.path.dirname(os.path.abspath(__file__))


def run_test(name: str, script: str) -> bool:
    path = os.path.join(_TESTS, script)
    if not os.path.exists(path):
        print(f"  [SKIP] {name} -- file not found: {script}")
        return False

    print(f"\n{'='*64}")
    print(f"  RUNNING: {name}")
    print(f"{'='*64}")

    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'

    result = subprocess.run(
        [sys.executable, path],
        capture_output=True, text=True,
        encoding='utf-8', errors='replace',
        cwd=os.path.dirname(_TESTS),  # backend/
        env=env,
    )
    # Print stdout (the test output)
    if result.stdout:
        for line in result.stdout.strip().split('\n'):
            # Replace problematic chars for Windows console
            safe = line.encode('ascii', 'replace').decode('ascii')
            print(f"  {safe}")
    # Print stderr if there were warnings/errors (filter noise)
    if result.returncode != 0 and result.stderr:
        err_lines = [l for l in result.stderr.strip().split('\n')
                     if 'Traceback' in l or 'Error' in l or 'FAIL' in l or 'assert' in l.lower()]
        for line in err_lines[:10]:
            safe = line.encode('ascii', 'replace').decode('ascii')
            print(f"  STDERR: {safe}")

    return result.returncode == 0


def main():
    print("=" * 64)
    print("  SECUIR MODEL VERIFICATION SUITE")
    print("=" * 64)

    tests = [
        ("1. Model Loading",          "test_model_loading.py"),
        ("2. Baseline Hierarchy",     "test_baseline_hierarchy.py"),
        ("3. Model Predictions",      "test_model_predictions.py"),
        ("4. Inference Speed",        "test_model_performance.py"),
        ("5. Baseline Tests (unit)",  "test_baseline.py"),
        ("6. Full System Tests",      "test_full_system.py"),
    ]

    t0 = time.time()
    results = []

    for name, script in tests:
        passed = run_test(name, script)
        results.append((name, passed))

    elapsed = time.time() - t0

    # Summary
    print(f"\n{'='*64}")
    print(f"  TEST SUMMARY  ({elapsed:.1f}s)")
    print(f"{'='*64}")

    for name, passed in results:
        status = "[OK]  " if passed else "[FAIL]"
        print(f"  {status} {name}")

    passed_count = sum(1 for _, p in results if p)
    total = len(results)

    print(f"\n  Total: {passed_count}/{total} passed")

    if passed_count == total:
        print("\n  ALL TESTS PASSED. Models are production-ready.")
    else:
        failed = [n for n, p in results if not p]
        print(f"\n  Failed: {', '.join(failed)}")

    return passed_count == total


if __name__ == '__main__':
    ok = main()
    sys.exit(0 if ok else 1)
