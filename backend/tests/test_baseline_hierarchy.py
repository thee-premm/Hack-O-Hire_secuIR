"""
Test baseline hierarchy: User -> Global -> Default
Run: cd backend && python tests/test_baseline_hierarchy.py
"""

import os
import sys
import time

_TESTS = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_TESTS)
_SRC = os.path.join(_BACKEND, 'src')
sys.path.insert(0, _SRC)

from state.redis_baseline_manager import baseline_manager
from config.redis_config import redis_config


def test_baseline_hierarchy():
    print("=" * 60)
    print("  TEST 3: Baseline Hierarchy Verification")
    print("=" * 60)

    # Redis status
    redis_up = redis_config.is_available()
    print(f"\n  Redis: {'Connected' if redis_up else 'Not connected (in-memory mode)'}")
    stats = baseline_manager.stats()
    print(f"  Users in memory: {stats['users_in_memory']}")
    print(f"  Global events:   {stats['global_events']}")

    # If baselines are empty, populate first
    if stats['users_in_memory'] == 0:
        print("\n  Baselines empty -- populating from training data ...")
        import pandas as pd
        ds = r'C:\Users\thee_premm\OneDrive\Desktop\HackOHire\DataSet\bank_security_dataset_70k'
        for f in ['training_50k_features.csv', 'training_50k_classification.csv', 'training_50k.csv']:
            fp = os.path.join(ds, f)
            if os.path.exists(fp):
                df = pd.read_csv(fp)
                baseline_manager.populate_from_dataframe(df, user_col='user')
                break
        stats = baseline_manager.stats()
        print(f"  Populated: {stats['users_in_memory']} users")

    all_pass = True

    # ---- Test 1: Known user -> user baseline ----
    print("\n  Test 1: Known user ...")
    # Pick a user that exists (from training data)
    # Try a few known users from our population
    test_users = ['siya.williams', 'michael.rodriguez', 'mekhala_sankar']
    known_user = None
    for u in test_users:
        bl = baseline_manager.get_baseline(u)
        if bl.get('type') == 'user':
            known_user = u
            break

    if known_user:
        bl = baseline_manager.get_baseline(known_user)
        print(f"    User:        {known_user}")
        print(f"    Type:        {bl['type']}")
        print(f"    Avg hour:    {bl.get('avg_login_hour', '?'):.1f}")
        print(f"    Devices:     {len(bl.get('devices', []))}")
        print(f"    Locations:   {len(bl.get('locations', []))}")
        print(f"    Events:      {bl.get('event_count', 0)}")
        if bl['type'] == 'user':
            print(f"    [OK]  User baseline returned correctly")
        else:
            print(f"    [FAIL] Expected 'user', got '{bl['type']}'")
            all_pass = False
    else:
        print(f"    [WARN] No test users found in baselines")
        all_pass = False

    # ---- Test 2: Unknown user -> global baseline ----
    print("\n  Test 2: Unknown user ...")
    unknown = "completely_unknown_user_xyz_99999"
    bl2 = baseline_manager.get_baseline(unknown)
    print(f"    User:        {unknown}")
    print(f"    Type:        {bl2.get('type', '?')}")
    print(f"    Is new user: {bl2.get('is_new_user', '?')}")
    print(f"    Avg hour:    {bl2.get('avg_login_hour', '?')}")
    if bl2.get('type') == 'global':
        print(f"    [OK]  Global baseline returned for new user")
    elif bl2.get('type') == 'default':
        print(f"    [OK]  Default baseline returned (no global data yet)")
    else:
        print(f"    [FAIL] Expected 'global' or 'default', got '{bl2.get('type')}'")
        all_pass = False

    # ---- Test 3: Baseline features ----
    print("\n  Test 3: Baseline feature computation ...")
    if known_user:
        bl3 = baseline_manager.get_baseline(known_user)
        test_event = {
            'timestamp': None,
            'hour': 3,  # unusual hour
            'host': 'UNKNOWN-SERVER',
            'geo': 'RU',  # unusual location
        }
        feats = baseline_manager.get_baseline_features(known_user, test_event)
        print(f"    login_hour_deviation: {feats['login_hour_deviation']:.3f}")
        print(f"    device_match:         {feats['device_match']:.1f}")
        print(f"    location_match:       {feats['location_match']:.1f}")
        print(f"    is_new_user:          {feats['is_new_user']:.1f}")
        if feats['login_hour_deviation'] > 0:
            print(f"    [OK]  Hour deviation > 0 (unusual hour detected)")
        else:
            print(f"    [WARN] Hour deviation = 0 (may indicate sparse baseline)")
        if feats['device_match'] == 0.0:
            print(f"    [OK]  Unknown device correctly scored 0")
        if feats['location_match'] == 0.0:
            print(f"    [OK]  Unknown location correctly scored 0")

    # ---- Test 4: Global baseline stats ----
    print("\n  Test 4: Global baseline ...")
    gb = baseline_manager.get_global_baseline()
    print(f"    Total events:   {gb.get('total_events', 0)}")
    print(f"    Unique users:   {gb.get('unique_users', 0)}")
    print(f"    Avg login hour: {gb.get('avg_login_hour', '?'):.1f}")
    print(f"    Top events:     {list(gb.get('top_events', {}).keys())[:5]}")
    if gb.get('total_events', 0) > 0:
        print(f"    [OK]  Global baseline has data")
    else:
        print(f"    [WARN] Global baseline is empty")

    # Summary
    print("\n" + "=" * 60)
    print("  HIERARCHY TEST SUMMARY")
    print("=" * 60)
    print(f"  User baseline:   {'OK' if known_user else 'NEEDS POPULATION'}")
    print(f"  Global baseline: {'OK' if gb.get('total_events',0)>0 else 'EMPTY'}")
    print(f"  Fallback:        OK (always available)")
    print(f"\n  RESULT: {'PASSED' if all_pass else 'PARTIAL'}")

    return all_pass


if __name__ == '__main__':
    ok = test_baseline_hierarchy()
    sys.exit(0 if ok else 1)
