"""
Populate Redis/in-memory baselines from training data.
Run: cd backend && python scripts/populate_baselines.py

This MUST be run before model training so the models learn
real user deviation patterns from the 70K dataset.
"""

import sys
import os
import time

# Add backend/src to path
_BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC = os.path.join(_BACKEND, 'src')
sys.path.insert(0, _SRC)

import pandas as pd
import numpy as np
import json
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


def main():
    print("=" * 65)
    print("  SECUIR -- BASELINE POPULATION FROM TRAINING DATA")
    print("=" * 65)

    # Import after path setup
    from state.redis_baseline_manager import baseline_manager
    from config.redis_config import redis_config

    # Check Redis
    if redis_config.is_available():
        print("\n  [OK] Redis connected - using Redis + in-memory dual mode")
    else:
        print("\n  [INFO] Redis not available - using in-memory mode (fully functional)")

    # ---- Dataset path ----
    DATASET_DIR = os.getenv(
        'SECUIR_DATASET',
        r'C:\Users\thee_premm\OneDrive\Desktop\HackOHire\DataSet\bank_security_dataset_70k'
    )

    # Try training files in priority order
    candidates = [
        os.path.join(DATASET_DIR, 'training_50k_features.csv'),     # has pre-computed features
        os.path.join(DATASET_DIR, 'training_50k.csv'),               # raw training
        os.path.join(DATASET_DIR, 'training_50k_classification.csv'),
    ]

    df = None
    for fpath in candidates:
        if os.path.exists(fpath):
            print(f"\n  Loading: {os.path.basename(fpath)}")
            t0 = time.time()
            df = pd.read_csv(fpath)
            print(f"  Loaded {len(df)} rows in {time.time()-t0:.1f}s")
            print(f"  Columns: {list(df.columns)[:10]}...")
            break

    if df is None:
        # Fall back to main dataset
        main_csv = os.path.join(os.path.dirname(DATASET_DIR), 'synthetic_bank_logs_70000_robust.csv')
        if os.path.exists(main_csv):
            print(f"\n  Loading main dataset: synthetic_bank_logs_70000_robust.csv")
            t0 = time.time()
            df = pd.read_csv(main_csv)
            print(f"  Loaded {len(df)} rows in {time.time()-t0:.1f}s")
        else:
            print(f"\n  ERROR: No dataset found at {DATASET_DIR}")
            print(f"  Set SECUIR_DATASET env var to your dataset path")
            sys.exit(1)

    # Detect user column
    user_col = 'user' if 'user' in df.columns else 'user_id'
    n_users = df[user_col].nunique()
    print(f"  Unique users: {n_users}")
    print(f"  Severity distribution: {df['severity'].value_counts().to_dict()}")

    # ---- Populate ----
    print(f"\n  Populating baselines for {n_users} users...")
    print("  This may take 1-3 minutes...\n")

    t0 = time.time()
    summary = baseline_manager.populate_from_dataframe(df, user_col=user_col, batch_log_every=10000)
    elapsed = time.time() - t0

    # ---- Results ----
    print("\n" + "=" * 65)
    print("  POPULATION COMPLETE")
    print("=" * 65)
    print(f"  Events processed : {summary['events_processed']}")
    print(f"  Users populated  : {summary['users_populated']}")
    print(f"  Time             : {elapsed:.1f}s")
    print(f"  Redis mode       : {summary['redis_mode']}")

    # Global baseline
    gb = baseline_manager.get_global_baseline()
    print(f"\n  Global Baseline:")
    print(f"    Avg login hour  : {gb.get('avg_login_hour', 0):.1f}")
    print(f"    Std login hour  : {gb.get('std_login_hour', 0):.1f}")
    print(f"    Total events    : {gb.get('total_events', 0)}")
    print(f"    Unique users    : {gb.get('unique_users', 0)}")
    print(f"    Top events      : {list(gb.get('top_events', {}).keys())[:5]}")

    # Sample user baselines
    print(f"\n  Sample User Baselines:")
    sample_users = df[user_col].dropna().unique()[:5]
    for uid in sample_users:
        bl = baseline_manager.get_baseline(str(uid))
        print(f"    {uid}: type={bl['type']}, avg_hour={bl.get('avg_login_hour',0):.1f}, "
              f"devices={len(bl.get('devices',[]))}, locations={len(bl.get('locations',[]))}, "
              f"events={bl.get('event_count',0)}")

    # Test new user (should get global baseline)
    print(f"\n  New User Test (never-seen user):")
    new_bl = baseline_manager.get_baseline('brand_new_user_12345')
    print(f"    type={new_bl['type']}, is_new_user={new_bl.get('is_new_user', False)}, "
          f"avg_hour={new_bl.get('avg_login_hour',0):.1f}")

    # Test baseline features
    from features.baseline_feature_builder import baseline_feature_builder
    print(f"\n  Baseline Feature Test:")
    test_event = {
        'timestamp': pd.Timestamp('2026-03-28T03:00:00'),
        'event': 'Suspicious',
        'severity': 'CRITICAL',
        'host': 'UNKNOWN-HOST',
        'ip': '55.66.77.88',
        'source': 'sentinel_one',
        'message': 'Suspicious: test_user performed payment operation',
    }
    test_user = str(sample_users[0])
    feats = baseline_feature_builder.compute_deviation_features(test_event, test_user)
    print(f"    User: {test_user}")
    for k, v in sorted(feats.items()):
        print(f"      {k}: {v:.3f}")

    # Save summary
    summary_path = os.path.join(_SRC, 'models', 'baseline_summary.json')
    os.makedirs(os.path.dirname(summary_path), exist_ok=True)
    save_data = {
        'populated_at': time.strftime('%Y-%m-%dT%H:%M:%S'),
        'events_processed': summary['events_processed'],
        'users_populated': summary['users_populated'],
        'elapsed_seconds': round(elapsed, 1),
        'global_avg_login_hour': round(gb.get('avg_login_hour', 0), 2),
        'global_std_login_hour': round(gb.get('std_login_hour', 0), 2),
        'severity_distribution': gb.get('severity_distribution', {}),
    }
    with open(summary_path, 'w') as f:
        json.dump(save_data, f, indent=2)
    print(f"\n  Summary saved: {summary_path}")

    print("\n  DONE. Baselines ready for model training.")
    print("=" * 65)


if __name__ == '__main__':
    main()
