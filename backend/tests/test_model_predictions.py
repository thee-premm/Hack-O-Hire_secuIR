"""
Test model predictions with sample events.
Uses the real FastFeatureLoader and baseline manager.
Run: cd backend && python tests/test_model_predictions.py
"""

import os
import sys
import pickle
import numpy as np
import pandas as pd

_TESTS = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_TESTS)
_SRC = os.path.join(_BACKEND, 'src')
sys.path.insert(0, _SRC)

from state.redis_baseline_manager import baseline_manager
from models.fast_feature_loader import FastFeatureLoader

MODEL_DIR = os.path.join(_SRC, 'models')


def _ensure_baselines():
    """Populate baselines if empty."""
    if baseline_manager.stats()['users_in_memory'] > 0:
        return
    ds = r'C:\Users\thee_premm\OneDrive\Desktop\HackOHire\DataSet\bank_security_dataset_70k'
    for f in ['training_50k_features.csv', 'training_50k_classification.csv']:
        fp = os.path.join(ds, f)
        if os.path.exists(fp):
            df = pd.read_csv(fp)
            baseline_manager.populate_from_dataframe(df, user_col='user')
            return


def test_predictions():
    print("=" * 60)
    print("  TEST 2: Model Predictions Verification")
    print("=" * 60)

    _ensure_baselines()

    # Load models
    try:
        with open(os.path.join(MODEL_DIR, 'lr_model.pkl'), 'rb') as f:
            lr, lr_scaler = pickle.load(f)
        with open(os.path.join(MODEL_DIR, 'iso_model.pkl'), 'rb') as f:
            iso, iso_scaler = pickle.load(f)
        with open(os.path.join(MODEL_DIR, 'xgb_model.pkl'), 'rb') as f:
            xgb_model = pickle.load(f)
        print("  Models loaded.\n")
    except Exception as e:
        print(f"  [FAIL] Cannot load models: {e}")
        return False

    # ---- Test events using DATASET columns ----
    # Columns the feature loader expects:
    #   user, hour, day_of_week, month, is_weekend, is_off_hours,
    #   message_length, has_ip, has_error, has_attempts, attempts,
    #   severity, source, event, ip, message, host, geo
    test_events = [
        {
            'label': 'Normal login (LOW severity)',
            'user': 'siya.williams',   # known user
            'event': 'login', 'severity': 'LOW', 'source': 'azure_ad',
            'ip': '10.0.0.50', 'host': 'WKS-01',
            'message': 'User logged in successfully',
            'hour': 10, 'day_of_week': 2, 'month': 3,
            'is_weekend': 0, 'is_off_hours': 0,
            'message_length': 32, 'has_ip': 0, 'has_error': 0,
            'has_attempts': 0, 'attempts': 0,
            'geo': 'US',
            'expected_risk': 'LOW',
        },
        {
            'label': 'Suspicious off-hours (CRITICAL severity)',
            'user': 'brand_new_attacker',  # unknown user
            'event': 'Suspicious', 'severity': 'CRITICAL', 'source': 'sentinel_one',
            'ip': '55.66.77.88', 'host': 'UNKNOWN-SERVER',
            'message': 'Suspicious: attacker performed payment transfer',
            'hour': 3, 'day_of_week': 6, 'month': 3,
            'is_weekend': 1, 'is_off_hours': 1,
            'message_length': 52, 'has_ip': 1, 'has_error': 1,
            'has_attempts': 1, 'attempts': 5,
            'geo': 'NG',
            'expected_risk': 'HIGH',
        },
        {
            'label': 'Medium severity detection event',
            'user': 'michael.rodriguez',  # known user
            'event': 'Detection', 'severity': 'HIGH', 'source': 'crowdstrike',
            'ip': '192.168.1.100', 'host': 'APP-30',
            'message': 'Detection: michael.rodriguez triggered alert',
            'hour': 14, 'day_of_week': 3, 'month': 3,
            'is_weekend': 0, 'is_off_hours': 0,
            'message_length': 48, 'has_ip': 1, 'has_error': 0,
            'has_attempts': 0, 'attempts': 0,
            'geo': 'US',
            'expected_risk': 'MEDIUM-HIGH',
        },
        {
            'label': 'Admin off-hours file download',
            'user': 'svc_admin_deploy',  # service account
            'event': 'FileDownloaded', 'severity': 'MEDIUM', 'source': 'sharepoint',
            'ip': '10.35.23.170', 'host': 'CORE_BANK-14',
            'message': 'FileDownloaded: svc_admin_deploy exported sensitive data',
            'hour': 23, 'day_of_week': 5, 'month': 3,
            'is_weekend': 0, 'is_off_hours': 1,
            'message_length': 55, 'has_ip': 0, 'has_error': 0,
            'has_attempts': 0, 'attempts': 0,
            'geo': 'IN',
            'expected_risk': 'MEDIUM',
        },
    ]

    loader = FastFeatureLoader()
    results = []

    print(f"  {'Event':<45} {'Baseline':<8} {'LR':>6} {'XGB':>6} {'ISO':>6} {'Ens':>6}  Action")
    print(f"  {'-'*100}")

    for ev in test_events:
        user = ev['user']
        label = ev.pop('label')
        expected = ev.pop('expected_risk')

        # Get baseline type
        bl = baseline_manager.get_baseline(user)
        bl_type = bl.get('type', '?')

        # Build feature vectors from single-row DataFrame
        df = pd.DataFrame([ev])

        # Use internal methods (load_and_prepare expects file path)
        bl_df = loader._compute_baseline_features_vectorized(df, 'user')
        X_core = loader._build_core(df, bl_df)
        X_full, _ = loader._build_full(df, bl_df)

        # LR
        X_lr_s = lr_scaler.transform(X_core)
        lr_prob = float(lr.predict_proba(X_lr_s)[0][1])

        # XGB
        xgb_prob = float(xgb_model.predict_proba(X_full)[0][1])

        # ISO
        X_iso_s = iso_scaler.transform(X_core)
        iso_raw = iso.decision_function(X_iso_s)
        iso_prob = float(1 / (1 + np.exp(iso_raw[0])))

        # Ensemble
        ens_prob = 0.3 * lr_prob + 0.5 * xgb_prob + 0.2 * iso_prob

        if ens_prob > 0.7:
            action = "BLOCK"
        elif ens_prob > 0.4:
            action = "MFA_CHALLENGE"
        else:
            action = "LOG_ONLY"

        print(f"  {label:<45} {bl_type:<8} {lr_prob:6.3f} {xgb_prob:6.3f} "
              f"{iso_prob:6.3f} {ens_prob:6.3f}  {action}")

        results.append({
            'label': label, 'user': user, 'baseline': bl_type,
            'lr': lr_prob, 'xgb': xgb_prob, 'iso': iso_prob,
            'ensemble': ens_prob, 'action': action, 'expected': expected,
        })

        ev['label'] = label
        ev['expected_risk'] = expected

    # ---- Expectation checks ----
    print(f"\n  Expectation Checks:")
    all_ok = True

    # New user should get global baseline
    attacker = next(r for r in results if r['user'] == 'brand_new_attacker')
    if attacker['baseline'] in ('global', 'default'):
        print(f"  [OK]  New user got '{attacker['baseline']}' baseline")
    else:
        print(f"  [FAIL] New user got '{attacker['baseline']}' (expected global/default)")
        all_ok = False

    # Critical suspicious event should be high risk
    if attacker['ensemble'] > 0.4:
        print(f"  [OK]  Suspicious CRITICAL event: risk={attacker['ensemble']:.3f} (elevated)")
    else:
        print(f"  [WARN] Suspicious event risk={attacker['ensemble']:.3f} (expected >0.4)")

    # Normal LOW event should be low risk
    normal = next(r for r in results if r['expected'] == 'LOW')
    if normal['ensemble'] < 0.5:
        print(f"  [OK]  Normal LOW event: risk={normal['ensemble']:.3f} (low)")
    else:
        print(f"  [WARN] Normal event risk={normal['ensemble']:.3f} (expected <0.5)")

    # XGBoost should distinguish severity well
    low_xgb = normal['xgb']
    high_xgb = attacker['xgb']
    if high_xgb > low_xgb:
        print(f"  [OK]  XGBoost correctly ranks CRITICAL ({high_xgb:.3f}) > LOW ({low_xgb:.3f})")
    else:
        print(f"  [WARN] XGBoost ranking unexpected: CRITICAL={high_xgb:.3f}, LOW={low_xgb:.3f}")

    print(f"\n  RESULT: {'PASSED' if all_ok else 'PARTIAL'}")
    return all_ok


if __name__ == '__main__':
    ok = test_predictions()
    sys.exit(0 if ok else 1)
