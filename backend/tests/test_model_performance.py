"""
Test model inference speed.
Run: cd backend && python tests/test_model_performance.py
"""

import os
import sys
import time
import pickle
import numpy as np

_TESTS = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_TESTS)
_SRC = os.path.join(_BACKEND, 'src')
sys.path.insert(0, _SRC)

MODEL_DIR = os.path.join(_SRC, 'models')


def test_inference_speed(n_events=1000):
    print("=" * 60)
    print("  TEST 4: Model Inference Speed")
    print("=" * 60)

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

    np.random.seed(42)
    n_core = lr.coef_.shape[1]   # 11
    n_full = xgb_model.n_features_in_ if hasattr(xgb_model, 'n_features_in_') else 15

    X_core = np.random.randn(n_events, n_core)
    X_full = np.random.randn(n_events, n_full)

    X_core_s = lr_scaler.transform(X_core)
    X_core_iso_s = iso_scaler.transform(X_core)

    all_ok = True

    # ---- LR ----
    t0 = time.perf_counter()
    _ = lr.predict_proba(X_core_s)
    lr_ms = (time.perf_counter() - t0) * 1000
    lr_per = lr_ms / n_events
    ok = lr_per < 5
    print(f"  LR          {lr_ms:8.2f} ms total   {lr_per:.4f} ms/event   {'[OK]' if ok else '[SLOW]'}")
    all_ok &= ok

    # ---- Isolation Forest ----
    t0 = time.perf_counter()
    _ = iso.decision_function(X_core_iso_s)
    iso_ms = (time.perf_counter() - t0) * 1000
    iso_per = iso_ms / n_events
    ok = iso_per < 5
    print(f"  ISO         {iso_ms:8.2f} ms total   {iso_per:.4f} ms/event   {'[OK]' if ok else '[SLOW]'}")
    all_ok &= ok

    # ---- XGBoost ----
    t0 = time.perf_counter()
    _ = xgb_model.predict_proba(X_full)
    xgb_ms = (time.perf_counter() - t0) * 1000
    xgb_per = xgb_ms / n_events
    ok = xgb_per < 10
    print(f"  XGB         {xgb_ms:8.2f} ms total   {xgb_per:.4f} ms/event   {'[OK]' if ok else '[SLOW]'}")
    all_ok &= ok

    # ---- Full ensemble pipeline ----
    t0 = time.perf_counter()
    lr_p = lr.predict_proba(X_core_s)[:, 1]
    iso_r = iso.decision_function(X_core_iso_s)
    iso_p = 1 / (1 + np.exp(iso_r))
    xgb_p = xgb_model.predict_proba(X_full)[:, 1]
    ens = 0.3 * lr_p + 0.5 * xgb_p + 0.2 * iso_p
    ens_ms = (time.perf_counter() - t0) * 1000
    ens_per = ens_ms / n_events
    ok = ens_per < 15
    print(f"  Ensemble    {ens_ms:8.2f} ms total   {ens_per:.4f} ms/event   {'[OK]' if ok else '[SLOW]'}")
    all_ok &= ok

    # ---- Single event latency (worst case) ----
    print(f"\n  Single-event latency:")
    for name, model, scaler, X_single in [
        ('LR', lr, lr_scaler, X_core[:1]),
        ('XGB', xgb_model, None, X_full[:1]),
    ]:
        times = []
        for _ in range(100):
            x = scaler.transform(X_single) if scaler else X_single
            t0 = time.perf_counter()
            _ = model.predict_proba(x)
            times.append((time.perf_counter() - t0) * 1000)
        avg = np.mean(times)
        p99 = np.percentile(times, 99)
        print(f"    {name:5s}  avg={avg:.3f}ms  p99={p99:.3f}ms")

    print(f"\n  Tested on {n_events} events.")
    print(f"  RESULT: {'PASSED' if all_ok else 'SOME TARGETS MISSED'}")
    return all_ok


if __name__ == '__main__':
    ok = test_inference_speed()
    sys.exit(0 if ok else 1)
