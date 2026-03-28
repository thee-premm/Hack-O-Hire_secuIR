"""
Fast Model Trainer
Trains LR + Isolation Forest + XGBoost on the 70K dataset.
Optimized for speed: uses pre-computed features, minimal tuning, all cores.

Run:
    cd backend
    python src/models/fast_trainer.py
"""

import os
import sys
import pickle
import json
import time
import numpy as np
import logging
from datetime import datetime

_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, roc_auc_score, classification_report, confusion_matrix,
)

import xgboost as xgb

from models.fast_feature_loader import FastFeatureLoader

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ---- Paths ----
DATASET_DIR = os.getenv(
    'SECUIR_DATASET',
    r'C:\Users\thee_premm\OneDrive\Desktop\HackOHire\DataSet\bank_security_dataset_70k'
)
MODEL_DIR = os.path.join(_SRC, 'models')


class FastModelTrainer:
    """
    Trains 3 models quickly:
      1. Logistic Regression on 11 core features  (fast, interpretable)
      2. Isolation Forest   on 11 core features  (unsupervised anomaly)
      3. XGBoost            on full feature set   (best accuracy)
    """

    def __init__(self, dataset_dir: str = DATASET_DIR, sample_frac: float = 1.0):
        self.dataset_dir = dataset_dir
        self.sample_frac = sample_frac
        self.loader = FastFeatureLoader()
        self.models = {}
        self.scalers = {}
        self.metrics = {}
        self.feature_names = {}

    # ==================================================================
    # MAIN ENTRY
    # ==================================================================

    def train_all(self) -> dict:
        banner = "FAST MODEL TRAINING"
        logger.info("=" * 64)
        logger.info(f"  {banner}")
        logger.info("=" * 64)
        t_start = time.time()

        # ---- Load training data ----
        train_path = os.path.join(self.dataset_dir, 'training_50k_classification.csv')
        if not os.path.exists(train_path):
            # Fallback to features CSV
            train_path = os.path.join(self.dataset_dir, 'training_50k_features.csv')
        logger.info(f"\n[1/5] Loading training data ...")
        X_core, X_full, y_train, full_names = self.loader.load_and_prepare(
            train_path, sample_frac=self.sample_frac
        )
        self.feature_names['full'] = full_names
        logger.info(f"  Core: {X_core.shape}, Full: {X_full.shape}, y: {y_train.shape}")

        # ---- Train models ----
        logger.info(f"\n[2/5] Training models ...")
        self._train_lr(X_core, y_train)
        self._train_iso(X_core)
        self._train_xgb(X_full, y_train, full_names)

        # ---- Evaluate on test set ----
        logger.info(f"\n[3/5] Evaluating on test set ...")
        self._evaluate()

        # ---- Calibrate thresholds ----
        logger.info(f"\n[4/5] Calibrating thresholds ...")
        self._calibrate()

        # ---- Save everything ----
        logger.info(f"\n[5/5] Saving models & metadata ...")
        self._save()

        elapsed = time.time() - t_start
        logger.info(f"\n{'='*64}")
        logger.info(f"  TRAINING COMPLETE  ({elapsed:.1f}s / {elapsed/60:.1f} min)")
        logger.info(f"{'='*64}")
        for name, m in self.metrics.items():
            logger.info(f"  {name:25s}  F1={m.get('f1',0):.4f}  AUC={m.get('roc_auc',0):.4f}")
        return self.metrics

    # ==================================================================
    # INDIVIDUAL MODEL TRAINERS
    # ==================================================================

    def _train_lr(self, X: np.ndarray, y: np.ndarray):
        logger.info("  [LR] Logistic Regression ...")
        t0 = time.time()
        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)
        model = LogisticRegression(
            C=1.0, class_weight='balanced', max_iter=200,
            solver='lbfgs', random_state=42, n_jobs=-1,
        )
        model.fit(X_s, y)
        self.models['lr'] = model
        self.scalers['lr'] = scaler
        logger.info(f"  [LR] Done in {time.time()-t0:.1f}s")

    def _train_iso(self, X: np.ndarray):
        logger.info("  [ISO] Isolation Forest ...")
        t0 = time.time()
        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)
        model = IsolationForest(
            n_estimators=100, contamination=0.10,
            random_state=42, n_jobs=-1,
        )
        model.fit(X_s)
        self.models['iso'] = model
        self.scalers['iso'] = scaler
        logger.info(f"  [ISO] Done in {time.time()-t0:.1f}s")

    def _train_xgb(self, X: np.ndarray, y: np.ndarray, feature_names: list):
        logger.info("  [XGB] XGBoost ...")
        t0 = time.time()
        pos = y.sum()
        neg = len(y) - pos
        spw = neg / max(pos, 1)
        model = xgb.XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.1,
            subsample=0.8, colsample_bytree=0.8,
            scale_pos_weight=spw,
            random_state=42, n_jobs=-1,
            eval_metric='logloss', verbosity=0,
            tree_method='hist',  # fastest method
        )
        model.fit(X, y)
        self.models['xgb'] = model
        self.feature_names['xgb'] = feature_names
        logger.info(f"  [XGB] Done in {time.time()-t0:.1f}s")

    # ==================================================================
    # EVALUATION
    # ==================================================================

    def _evaluate(self):
        test_path = os.path.join(self.dataset_dir, 'test_12k_classification.csv')
        if not os.path.exists(test_path):
            test_path = os.path.join(self.dataset_dir, 'test_12k_features.csv')
        X_core_t, X_full_t, y_test, _ = self.loader.load_and_prepare(test_path)

        # LR
        X_s = self.scalers['lr'].transform(X_core_t)
        y_pred_lr = self.models['lr'].predict(X_s)
        y_prob_lr = self.models['lr'].predict_proba(X_s)[:, 1]
        self.metrics['logistic_regression'] = self._score(y_test, y_pred_lr, y_prob_lr)

        # XGBoost
        y_pred_xgb = self.models['xgb'].predict(X_full_t)
        y_prob_xgb = self.models['xgb'].predict_proba(X_full_t)[:, 1]
        self.metrics['xgboost'] = self._score(y_test, y_pred_xgb, y_prob_xgb)

        # Isolation Forest
        X_s_iso = self.scalers['iso'].transform(X_core_t)
        raw = self.models['iso'].decision_function(X_s_iso)
        y_prob_iso = 1 / (1 + np.exp(raw))  # invert: lower decision_function = more anomalous
        y_pred_iso = (y_prob_iso > 0.5).astype(int)
        self.metrics['isolation_forest'] = self._score(y_test, y_pred_iso, y_prob_iso)

        # Ensemble
        y_prob_ens = 0.3 * y_prob_lr + 0.5 * y_prob_xgb + 0.2 * y_prob_iso
        y_pred_ens = (y_prob_ens > 0.5).astype(int)
        self.metrics['ensemble'] = self._score(y_test, y_pred_ens, y_prob_ens)

        # Print classification reports
        for name, y_pred, y_prob in [
            ('Logistic Regression', y_pred_lr, y_prob_lr),
            ('XGBoost', y_pred_xgb, y_prob_xgb),
            ('Ensemble', y_pred_ens, y_prob_ens),
        ]:
            logger.info(f"\n  === {name} ===")
            logger.info(f"  Accuracy:  {accuracy_score(y_test, y_pred):.4f}")
            logger.info(f"  Precision: {precision_score(y_test, y_pred, zero_division=0):.4f}")
            logger.info(f"  Recall:    {recall_score(y_test, y_pred, zero_division=0):.4f}")
            logger.info(f"  F1:        {f1_score(y_test, y_pred, zero_division=0):.4f}")
            logger.info(f"  ROC-AUC:   {roc_auc_score(y_test, y_prob):.4f}")

    def _calibrate(self):
        cal_path = os.path.join(self.dataset_dir, 'calibration_8k_classification.csv')
        if not os.path.exists(cal_path):
            cal_path = os.path.join(self.dataset_dir, 'calibration_8k_features.csv')
        if not os.path.exists(cal_path):
            logger.info("  No calibration file found, skipping")
            return

        X_core_c, X_full_c, y_cal, _ = self.loader.load_and_prepare(cal_path)

        # Find optimal threshold on calibration set
        X_s = self.scalers['lr'].transform(X_core_c)
        y_prob_lr = self.models['lr'].predict_proba(X_s)[:, 1]
        y_prob_xgb = self.models['xgb'].predict_proba(X_full_c)[:, 1]

        raw_iso = self.models['iso'].decision_function(self.scalers['iso'].transform(X_core_c))
        y_prob_iso = 1 / (1 + np.exp(raw_iso))

        y_prob_ens = 0.3 * y_prob_lr + 0.5 * y_prob_xgb + 0.2 * y_prob_iso

        best_f1 = 0
        best_thresh = 0.5
        for t in np.arange(0.2, 0.8, 0.02):
            preds = (y_prob_ens > t).astype(int)
            f = f1_score(y_cal, preds, zero_division=0)
            if f > best_f1:
                best_f1 = f
                best_thresh = t

        self.thresholds = {
            'optimal_threshold': round(float(best_thresh), 3),
            'calibration_f1': round(float(best_f1), 4),
            'high_risk_threshold': round(float(best_thresh), 3),
            'medium_risk_threshold': round(float(best_thresh * 0.6), 3),
            'low_risk_threshold': round(float(best_thresh * 0.3), 3),
        }
        logger.info(f"  Optimal threshold: {best_thresh:.3f} (F1={best_f1:.4f})")

    @staticmethod
    def _score(y_true, y_pred, y_prob) -> dict:
        return {
            'accuracy': round(float(accuracy_score(y_true, y_pred)), 4),
            'precision': round(float(precision_score(y_true, y_pred, zero_division=0)), 4),
            'recall': round(float(recall_score(y_true, y_pred, zero_division=0)), 4),
            'f1': round(float(f1_score(y_true, y_pred, zero_division=0)), 4),
            'roc_auc': round(float(roc_auc_score(y_true, y_prob)), 4),
            'confusion_matrix': confusion_matrix(y_true, y_pred).tolist(),
        }

    # ==================================================================
    # SAVE
    # ==================================================================

    def _save(self):
        os.makedirs(MODEL_DIR, exist_ok=True)

        # LR + scaler  (matches existing pipeline expectation)
        with open(os.path.join(MODEL_DIR, 'lr_model.pkl'), 'wb') as f:
            pickle.dump((self.models['lr'], self.scalers['lr']), f)
        logger.info(f"  Saved lr_model.pkl")

        # Isolation Forest + scaler
        with open(os.path.join(MODEL_DIR, 'iso_model.pkl'), 'wb') as f:
            pickle.dump((self.models['iso'], self.scalers['iso']), f)
        logger.info(f"  Saved iso_model.pkl")

        # XGBoost
        with open(os.path.join(MODEL_DIR, 'xgb_model.pkl'), 'wb') as f:
            pickle.dump(self.models['xgb'], f)
        logger.info(f"  Saved xgb_model.pkl")

        # Metrics
        with open(os.path.join(MODEL_DIR, 'model_metrics.json'), 'w') as f:
            json.dump(self.metrics, f, indent=2)
        logger.info(f"  Saved model_metrics.json")

        # Feature importance (XGBoost)
        importance = {}
        if 'xgb' in self.models and 'xgb' in self.feature_names:
            imp = self.models['xgb'].feature_importances_
            names = self.feature_names['xgb']
            importance['xgboost'] = {names[i]: round(float(imp[i]), 5) for i in np.argsort(imp)[::-1]}
        if 'lr' in self.models:
            coefs = self.models['lr'].coef_[0]
            core_names = FastFeatureLoader.CORE_FEATURE_NAMES
            importance['logistic_regression'] = {
                core_names[i]: round(float(abs(coefs[i])), 5)
                for i in np.argsort(np.abs(coefs))[::-1]
            }
        with open(os.path.join(MODEL_DIR, 'feature_importance.json'), 'w') as f:
            json.dump(importance, f, indent=2)
        logger.info(f"  Saved feature_importance.json")

        # Thresholds
        thresholds = getattr(self, 'thresholds', {
            'optimal_threshold': 0.5,
            'high_risk_threshold': 0.5,
            'medium_risk_threshold': 0.3,
            'low_risk_threshold': 0.15,
        })
        with open(os.path.join(MODEL_DIR, 'thresholds.json'), 'w') as f:
            json.dump(thresholds, f, indent=2)
        logger.info(f"  Saved thresholds.json")

        # Training metadata
        meta = {
            'trained_at': datetime.now().isoformat(),
            'dataset_dir': self.dataset_dir,
            'sample_fraction': self.sample_frac,
            'models': list(self.models.keys()),
            'feature_names': self.feature_names.get('xgb', []),
            'metrics_summary': {
                k: {'f1': v.get('f1', 0), 'roc_auc': v.get('roc_auc', 0)}
                for k, v in self.metrics.items()
            },
        }
        with open(os.path.join(MODEL_DIR, 'training_metadata.json'), 'w') as f:
            json.dump(meta, f, indent=2)
        logger.info(f"  Saved training_metadata.json")
        logger.info(f"  All models saved to {MODEL_DIR}")


# ==================================================================
# CLI
# ==================================================================

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Fast model trainer for SecuIR')
    parser.add_argument('--dataset', default=DATASET_DIR, help='Path to dataset folder')
    parser.add_argument('--sample', type=float, default=1.0,
                        help='Fraction of training data to use (0.3 = 30%%)')
    args = parser.parse_args()

    # First populate baselines if not already done
    from state.redis_baseline_manager import baseline_manager
    if baseline_manager.stats()['users_in_memory'] == 0:
        logger.info("Baselines empty, populating from training data first...")
        import pandas as pd
        feat_path = os.path.join(args.dataset, 'training_50k_features.csv')
        if os.path.exists(feat_path):
            df = pd.read_csv(feat_path)
        else:
            df = pd.read_csv(os.path.join(args.dataset, 'training_50k_classification.csv'))
        baseline_manager.populate_from_dataframe(df, user_col='user')
        logger.info(f"Populated {baseline_manager.stats()['users_in_memory']} user baselines\n")

    trainer = FastModelTrainer(dataset_dir=args.dataset, sample_frac=args.sample)
    trainer.train_all()
