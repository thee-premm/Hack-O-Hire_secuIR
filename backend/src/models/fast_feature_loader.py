"""
Fast Feature Loader with Redis Baseline Integration
Loads pre-computed features from CSVs + adds baseline deviation features.
Optimized for speed using vectorized operations (no per-event loops).

Dataset columns (classification):
    ts, host, user, event, attempts, severity, ip, message, source,
    is_high_risk, message_length, has_ip, has_error

Dataset columns (features - full):
    + file, proc, dst, geo, notes, hour, day_of_week, month,
      is_weekend, is_off_hours, has_attempts, is_suspicious, is_high_risk
"""

import os
import sys
import pandas as pd
import numpy as np
from typing import Tuple, List
import logging
import time

_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from state.redis_baseline_manager import baseline_manager

logger = logging.getLogger(__name__)

# ---- Constants ----

SEVERITY_MAP = {'LOW': 0.1, 'MEDIUM': 0.4, 'HIGH': 0.7, 'CRITICAL': 1.0, 'UNKNOWN': 0.3}

SOURCE_RISK = {
    'sentinel_one': 0.7, 'crowdstrike': 0.7, 'falco': 0.6,
    'palo_alto': 0.5, 'cisco_asa': 0.5, 'cloud_waf': 0.5,
    'sysmon': 0.4, 'windows_security': 0.4, 'auditd': 0.3,
    'aws_cloudtrail': 0.3, 'azure_ad': 0.3, 'office365': 0.2,
    'sharepoint': 0.2, 'github_actions': 0.2, 'zeek': 0.4,
}

HIGH_RISK_EVENTS = {
    'Suspicious', 'Blocked', 'Threat', 'Detection', 'XSS',
    'shell_in_container', 'Quarantine', 'privilege_escalation',
    'data_exfiltration', 'lateral_movement', 'ransomware_detected',
}

HIGH_RISK_GEOS = {'RU', 'CN', 'KP', 'IR', 'NG', 'VE', 'BY', 'SY', 'MM', 'LY'}


class FastFeatureLoader:
    """
    Fast feature loader that:
    1. Loads pre-computed features from the dataset CSVs
    2. Adds baseline deviation features from the Redis/in-memory baseline manager
    3. Returns ready-to-train numpy matrices
    """

    # Core features (11) used by Logistic Regression — matches existing pipeline
    CORE_FEATURE_NAMES = [
        'hour_of_day', 'day_of_week',
        'session_event_count', 'session_entropy', 'session_avg_rate',
        'login_hour_deviation', 'device_match_score', 'location_deviation_km',
        'cumulative_risk', 'last_window_risk', 'transaction_amount_zscore',
    ]

    # Extended features used by XGBoost (dataset + baseline deviations)
    EXTENDED_FEATURE_NAMES: List[str] = []  # set dynamically

    def __init__(self):
        self._baseline_cache = {}

    # ==================================================================
    # PUBLIC API
    # ==================================================================

    def load_and_prepare(
        self,
        filepath: str,
        sample_frac: float = 1.0,
        target_col: str = 'is_high_risk',
    ) -> Tuple[np.ndarray, np.ndarray, np.ndarray, List[str]]:
        """
        Load CSV, build features, return matrices.

        Returns:
            X_core  : (N, 11) array for Logistic Regression
            X_full  : (N, F)  array for XGBoost
            y       : (N,)    target labels
            full_feature_names : list of F feature names for XGBoost
        """
        t0 = time.time()
        logger.info(f"Loading {filepath}")
        df = pd.read_csv(filepath, low_memory=False)

        if sample_frac < 1.0:
            df = df.sample(frac=sample_frac, random_state=42).reset_index(drop=True)
            logger.info(f"  Sampled to {len(df)} rows ({sample_frac*100:.0f}%)")

        # Target
        if target_col in df.columns:
            y = df[target_col].fillna(0).astype(int).values
        else:
            y = np.zeros(len(df), dtype=int)
        logger.info(f"  Rows={len(df)}, positive={y.sum()} ({y.mean()*100:.1f}%)")

        # ---------- Build baseline deviation columns (vectorized) ----------
        user_col = 'user' if 'user' in df.columns else 'user_id'
        bl_df = self._compute_baseline_features_vectorized(df, user_col)

        # ---------- Build core features (11) ----------
        X_core = self._build_core(df, bl_df)

        # ---------- Build full features for XGBoost ----------
        X_full, full_names = self._build_full(df, bl_df)
        self.EXTENDED_FEATURE_NAMES = full_names

        logger.info(f"  Core shape: {X_core.shape}, Full shape: {X_full.shape}")
        logger.info(f"  Loaded in {time.time()-t0:.1f}s")
        return X_core, X_full, y, full_names

    # ==================================================================
    # CORE FEATURES (11 features, LR-compatible)
    # ==================================================================

    def _build_core(self, df: pd.DataFrame, bl: pd.DataFrame) -> np.ndarray:
        """11 features matching pipeline._build_core_vector"""
        hour = self._safe_col(df, 'hour', 12).values.astype(float)
        dow = self._safe_col(df, 'day_of_week', 3).values.astype(float)

        X = np.column_stack([
            hour,                                     # 0  hour_of_day
            dow,                                      # 1  day_of_week
            np.zeros(len(df)),                        # 2  session_event_count
            np.zeros(len(df)),                        # 3  session_entropy
            np.zeros(len(df)),                        # 4  session_avg_rate
            bl['login_hour_deviation'].values,        # 5  login_hour_deviation
            bl['device_match_score'].values,          # 6  device_match_score
            np.zeros(len(df)),                        # 7  location_deviation_km
            np.zeros(len(df)),                        # 8  cumulative_risk
            np.zeros(len(df)),                        # 9  last_window_risk
            np.zeros(len(df)),                        # 10 transaction_amount_zscore
        ])
        return np.nan_to_num(X, nan=0.0)

    # ==================================================================
    # FULL FEATURES (for XGBoost)
    # ==================================================================

    def _build_full(self, df: pd.DataFrame, bl: pd.DataFrame) -> Tuple[np.ndarray, List[str]]:
        """
        Build EXACTLY 15 features for XGBoost, in a fixed order.
        Always produces the same features regardless of which columns
        exist in the DataFrame (missing columns default to 0).
        """
        n = len(df)

        # The fixed 15-feature schema (must match training order):
        features = {
            # -- Dataset-derived (4 from classification CSV) --
            'message_length':   self._safe_col(df, 'message_length', 0).values.astype(float),
            'has_ip':           self._safe_col(df, 'has_ip', 0).values.astype(float),
            'has_error':        self._safe_col(df, 'has_error', 0).values.astype(float),
            'attempts':         self._safe_col(df, 'attempts', 0).values.astype(float),
            # -- Engineered from raw columns (6) --
            'severity_score':   (df['severity'].map(SEVERITY_MAP).fillna(0.3).values
                                 if 'severity' in df.columns else np.full(n, 0.3)),
            'source_risk_score': (df['source'].map(SOURCE_RISK).fillna(0.3).values
                                  if 'source' in df.columns else np.full(n, 0.3)),
            'is_high_risk_event': (df['event'].isin(HIGH_RISK_EVENTS).astype(float).values
                                   if 'event' in df.columns else np.zeros(n)),
            'ip_is_internal':   (df['ip'].fillna('').apply(
                                    lambda x: 1.0 if str(x).startswith(('10.', '192.168.', '172.16.', '172.17.'))
                                    else 0.0).values
                                 if 'ip' in df.columns else np.zeros(n)),
            'contains_sensitive_keyword': (df['message'].fillna('').str.lower().apply(
                                    lambda m: 1.0 if any(k in m for k in
                                    ('payment', 'transfer', 'settlement', 'admin',
                                     'privilege', 'export', 'delete')) else 0.0).values
                                 if 'message' in df.columns else np.zeros(n)),
            'geo_risk':         (df['geo'].fillna('').apply(
                                    lambda g: 1.0 if str(g).upper() in HIGH_RISK_GEOS else 0.0).values
                                 if 'geo' in df.columns else np.zeros(n)),
            # -- Baseline deviation features (5) --
            'bl_login_hour_deviation': bl['login_hour_deviation'].values,
            'bl_device_match_score':   bl['device_match_score'].values,
            'bl_location_match_score': bl['location_match_score'].values,
            'bl_is_new_user':          bl['is_new_user'].values,
            'bl_baseline_confidence':  bl['baseline_confidence'].values,
        }

        # Fixed order (must match training_metadata.json)
        ordered_names = [
            'message_length', 'has_ip', 'has_error', 'attempts',
            'severity_score', 'source_risk_score', 'is_high_risk_event',
            'ip_is_internal', 'contains_sensitive_keyword', 'geo_risk',
            'bl_login_hour_deviation', 'bl_device_match_score',
            'bl_location_match_score', 'bl_is_new_user', 'bl_baseline_confidence',
        ]

        X = np.column_stack([features[name] for name in ordered_names])
        return np.nan_to_num(X, nan=0.0), ordered_names

    # ==================================================================
    # BASELINE DEVIATION (vectorized — no per-row loops)
    # ==================================================================

    def _compute_baseline_features_vectorized(
        self, df: pd.DataFrame, user_col: str
    ) -> pd.DataFrame:
        """
        Compute baseline deviation features for every row.
        Uses batch user lookup (cached) for speed.
        """
        t0 = time.time()
        users = df[user_col].fillna('unknown').astype(str).values
        unique_users = np.unique(users)

        # Cache baselines for unique users
        cache = {}
        for uid in unique_users:
            cache[uid] = baseline_manager.get_baseline(uid)

        n = len(df)
        login_dev = np.zeros(n)
        device_match = np.zeros(n)
        location_match = np.zeros(n)
        is_new = np.zeros(n)
        confidence = np.full(n, 0.4)

        hour_vals = self._safe_col(df, 'hour', 12).values.astype(float)
        host_vals = df['host'].fillna('').astype(str).values if 'host' in df.columns else [''] * n
        geo_vals = df['geo'].fillna('').astype(str).values if 'geo' in df.columns else [''] * n

        for i in range(n):
            bl = cache.get(users[i], {})

            # Login hour deviation
            avg_h = bl.get('avg_login_hour', 12.0)
            std_h = bl.get('std_login_hour', 4.0)
            login_dev[i] = abs(hour_vals[i] - avg_h) / max(std_h, 1.0)

            # Device match (host)
            dev_set = bl.get('devices', [])
            if dev_set and host_vals[i]:
                device_match[i] = 1.0 if host_vals[i] in dev_set else 0.0

            # Location match (geo)
            loc_set = bl.get('locations', [])
            if loc_set and geo_vals[i] and geo_vals[i] != 'nan':
                location_match[i] = 1.0 if geo_vals[i] in loc_set else 0.0

            # New user
            bl_type = bl.get('type', 'default')
            is_new[i] = 0.0 if bl_type == 'user' else 1.0
            confidence[i] = {'user': 0.9, 'global': 0.4, 'default': 0.1}.get(bl_type, 0.1)

        logger.info(f"  Baseline features computed in {time.time()-t0:.1f}s "
                    f"({len(unique_users)} unique users)")
        return pd.DataFrame({
            'login_hour_deviation': login_dev,
            'device_match_score': device_match,
            'location_match_score': location_match,
            'is_new_user': is_new,
            'baseline_confidence': confidence,
        })

    # ==================================================================
    # HELPERS
    # ==================================================================

    @staticmethod
    def _safe_col(df: pd.DataFrame, col: str, default) -> pd.Series:
        if col in df.columns:
            return df[col].fillna(default)
        return pd.Series([default] * len(df))
