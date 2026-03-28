"""
Run All Backend Tests
Run: cd backend && python tests/run_all_tests.py
"""
import sys
import os
import time

# Add backend/src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import unittest


def run_all_tests():
    print("=" * 70)
    print("  SECUIR -- FULL TEST SUITE")
    print("=" * 70)
    start = time.time()

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Discover all test_*.py in this directory
    test_dir = os.path.dirname(os.path.abspath(__file__))
    discovered = loader.discover(test_dir, pattern="test_*.py")
    suite.addTests(discovered)

    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    elapsed = time.time() - start

    print("\n" + "=" * 70)
    print("  TEST SUMMARY")
    print("=" * 70)
    print(f"  Tests Run : {result.testsRun}")
    print(f"  Successes : {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"  Failures  : {len(result.failures)}")
    print(f"  Errors    : {len(result.errors)}")
    print(f"  Time      : {elapsed:.2f}s")

    if result.wasSuccessful():
        print("\n  ALL TESTS PASSED!")
    else:
        print("\n  SOME TESTS FAILED. Review output above.")

    return result.wasSuccessful()


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
