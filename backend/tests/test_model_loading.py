"""
Quick test to verify models are trained and loadable.
Run: cd backend && python tests/test_model_loading.py
"""

import os
import sys
import pickle
import json

_TESTS = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_TESTS)
_SRC = os.path.join(_BACKEND, 'src')
sys.path.insert(0, _SRC)

MODEL_DIR = os.path.join(_SRC, 'models')


def test_model_loading():
    print("=" * 60)
    print("  TEST 1: Model Loading Verification")
    print("=" * 60)

    # ---- Check files exist ----
    expected = {
        'lr_model.pkl': 'Logistic Regression + Scaler',
        'iso_model.pkl': 'Isolation Forest + Scaler',
        'xgb_model.pkl': 'XGBoost Classifier',
        'model_metrics.json': 'Evaluation metrics',
        'feature_importance.json': 'Feature importances',
        'thresholds.json': 'Risk thresholds',
        'training_metadata.json': 'Training metadata',
    }

    all_ok = True
    print()
    for fname, desc in expected.items():
        fpath = os.path.join(MODEL_DIR, fname)
        if os.path.exists(fpath):
            size_kb = os.path.getsize(fpath) / 1024
            print(f"  [OK]  {fname:30s}  {size_kb:8.1f} KB  ({desc})")
        else:
            print(f"  [MISSING]  {fname:30s}  ({desc})")
            all_ok = False

    if not all_ok:
        print("\n  Models missing. Run:  python src/models/fast_trainer.py")
        return False

    # ---- Load pickle models ----
    print("\n  Loading models ...")
    try:
        with open(os.path.join(MODEL_DIR, 'lr_model.pkl'), 'rb') as f:
            lr, lr_scaler = pickle.load(f)
        print(f"  [OK]  LR type={type(lr).__name__}, classes={lr.classes_}, "
              f"coef shape={lr.coef_.shape}")

        with open(os.path.join(MODEL_DIR, 'iso_model.pkl'), 'rb') as f:
            iso, iso_scaler = pickle.load(f)
        print(f"  [OK]  ISO type={type(iso).__name__}, "
              f"n_estimators={iso.n_estimators}")

        with open(os.path.join(MODEL_DIR, 'xgb_model.pkl'), 'rb') as f:
            xgb_model = pickle.load(f)
        n_feat = xgb_model.n_features_in_ if hasattr(xgb_model, 'n_features_in_') else '?'
        print(f"  [OK]  XGB type={type(xgb_model).__name__}, "
              f"n_features={n_feat}, n_estimators={xgb_model.n_estimators}")
    except Exception as e:
        print(f"  [FAIL]  Error loading models: {e}")
        return False

    # ---- Load JSON metadata ----
    print("\n  Loading metadata ...")
    try:
        with open(os.path.join(MODEL_DIR, 'model_metrics.json')) as f:
            metrics = json.load(f)
        print(f"  [OK]  Metrics for: {list(metrics.keys())}")
        for name, m in metrics.items():
            print(f"         {name:25s}  F1={m.get('f1',0):.4f}  AUC={m.get('roc_auc',0):.4f}")

        with open(os.path.join(MODEL_DIR, 'feature_importance.json')) as f:
            importance = json.load(f)
        for model_name, feats in importance.items():
            top3 = list(feats.items())[:3]
            print(f"  [OK]  {model_name} top features: "
                  f"{', '.join(f'{k}={v:.4f}' for k,v in top3)}")

        with open(os.path.join(MODEL_DIR, 'thresholds.json')) as f:
            thresholds = json.load(f)
        print(f"  [OK]  Thresholds: {thresholds}")

    except Exception as e:
        print(f"  [FAIL]  Error loading metadata: {e}")
        return False

    print(f"\n  All models and metadata loaded successfully.")
    return True


if __name__ == '__main__':
    ok = test_model_loading()
    print(f"\n  RESULT: {'PASSED' if ok else 'FAILED'}")
    sys.exit(0 if ok else 1)
