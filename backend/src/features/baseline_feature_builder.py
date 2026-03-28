"""
Baseline Feature Builder
Computes deviation features using hierarchical baselines (user -> global -> default).
Used by both the training pipeline and real-time inference.
"""

import numpy as np
import os
import sys
from typing import Dict
from datetime import datetime

_SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from state.redis_baseline_manager import baseline_manager


class BaselineFeatureBuilder:
    """
    Compute deviation features using Redis/in-memory baselines.
    Outputs features ready for model consumption.
    """

    # Known high-risk geolocations
    HIGH_RISK_GEOS = {'RU', 'CN', 'KP', 'IR', 'NG', 'VE', 'BY', 'SY', 'MM', 'LY'}

    # Source risk weights (higher = more security-relevant source)
    SOURCE_RISK = {
        'sentinel_one': 0.7, 'crowdstrike': 0.7, 'falco': 0.6,
        'palo_alto': 0.5, 'cisco_asa': 0.5, 'cloud_waf': 0.5,
        'sysmon': 0.4, 'windows_security': 0.4, 'auditd': 0.3,
        'aws_cloudtrail': 0.3, 'azure_ad': 0.3, 'office365': 0.2,
        'sharepoint': 0.2, 'github_actions': 0.2, 'zeek': 0.4,
    }

    # High-risk event names
    HIGH_RISK_EVENTS = {
        'Suspicious', 'Blocked', 'Threat', 'Detection', 'XSS',
        'shell_in_container', 'Quarantine', 'privilege_escalation',
        'data_exfiltration', 'lateral_movement', 'ransomware_detected',
    }

    # Severity mapping
    SEVERITY_MAP = {'LOW': 0.1, 'MEDIUM': 0.4, 'HIGH': 0.7, 'CRITICAL': 1.0, 'UNKNOWN': 0.3}

    def __init__(self):
        self.bl_manager = baseline_manager

    def compute_deviation_features(self, event: Dict, user_id: str) -> Dict[str, float]:
        """
        Compute all deviation features for a single event.
        Returns flat dict of numeric features.
        """
        baseline = self.bl_manager.get_baseline(user_id)

        # --- Extract event data ---
        hour = self._get_hour(event)
        device = event.get('device_id') or event.get('proc') or event.get('host') or ''
        location = event.get('location_country') or event.get('geo') or ''
        ev_type = str(event.get('event_type') or event.get('event') or '')
        severity = str(event.get('severity') or 'UNKNOWN')
        source = str(event.get('source') or '')
        ip = str(event.get('ip_address') or event.get('ip') or '')
        message = str(event.get('message') or '')
        attempts = float(event.get('attempts', 0) or 0)

        features = {}

        # 1. Login hour deviation (z-score)
        avg_h = baseline.get('avg_login_hour', 12.0)
        std_h = baseline.get('std_login_hour', 4.0)
        features['login_hour_deviation'] = abs(hour - avg_h) / max(std_h, 1.0)

        # 2. Device match score
        known_devices = set(baseline.get('devices', []))
        features['device_match_score'] = 1.0 if (device and device in known_devices) else 0.0

        # 3. Location match score
        known_locations = set(baseline.get('locations', []))
        features['location_match_score'] = 1.0 if (location and location in known_locations) else 0.0

        # 4. Is new user
        features['is_new_user'] = 1.0 if baseline.get('type') != 'user' else 0.0

        # 5. Baseline confidence
        bl_type = baseline.get('type', 'default')
        features['baseline_confidence'] = {'user': 0.9, 'global': 0.4, 'default': 0.1}.get(bl_type, 0.1)

        # 6. Severity score
        features['severity_score'] = self.SEVERITY_MAP.get(severity, 0.3)

        # 7. Source risk score
        features['source_risk_score'] = self.SOURCE_RISK.get(source, 0.3)

        # 8. Event risk category
        features['is_high_risk_event'] = 1.0 if ev_type in self.HIGH_RISK_EVENTS else 0.0

        # 9. Geo risk
        features['geo_risk'] = 1.0 if location.upper() in self.HIGH_RISK_GEOS else 0.0

        # 10. IP internal flag
        features['ip_is_internal'] = 1.0 if self._is_internal_ip(ip) else 0.0

        # 11. Attempts normalized
        features['attempts_norm'] = min(attempts / 5.0, 1.0) if attempts > 0 else 0.0

        # 12. Message length (normalized)
        features['message_length_norm'] = min(len(message) / 200.0, 1.0)

        # 13. Contains sensitive keywords
        msg_lower = message.lower()
        sensitive_kw = ['payment', 'transfer', 'settlement', 'admin', 'privilege', 'export', 'delete']
        features['contains_sensitive_keyword'] = 1.0 if any(k in msg_lower for k in sensitive_kw) else 0.0

        # 14. Off-hours flag
        features['is_off_hours'] = 1.0 if (hour < 6 or hour > 22) else 0.0

        # 15. Weekend flag
        ts = event.get('timestamp')
        if hasattr(ts, 'weekday'):
            features['is_weekend'] = 1.0 if ts.weekday() >= 5 else 0.0
        else:
            features['is_weekend'] = float(event.get('is_weekend', 0))

        # 16. User event diversity vs baseline
        user_unique = baseline.get('unique_events', 1)
        features['event_diversity_ratio'] = min(user_unique / 10.0, 1.0)

        return features

    def compute_core_vector(self, event: Dict, user_id: str, session_features: Dict = None) -> np.ndarray:
        """
        Build the 11-element core feature vector for Logistic Regression.
        Compatible with the existing pipeline's _build_core_vector.
        """
        dev = self.compute_deviation_features(event, user_id)
        hour = self._get_hour(event)
        ts = event.get('timestamp')
        dow = ts.weekday() if hasattr(ts, 'weekday') else int(event.get('day_of_week', 3))

        # Session features (passed in or defaults)
        sf = session_features or {}

        return np.array([
            hour,                                          # hour_of_day
            dow,                                           # day_of_week
            sf.get('session_event_count', 0),              # session_event_count
            sf.get('session_entropy', 0),                  # session_entropy
            sf.get('session_avg_rate', 0),                 # session_avg_rate
            dev['login_hour_deviation'],                   # login_hour_deviation
            dev['device_match_score'],                     # device_match_score
            0,                                             # location_deviation_km (simplified)
            sf.get('cumulative_risk', 0),                  # cumulative_risk
            sf.get('last_window_risk', 0),                 # last_window_risk
            0,                                             # transaction_amount_zscore
        ]).reshape(1, -1)

    def compute_extended_vector(self, event: Dict, user_id: str, session_features: Dict = None) -> Dict[str, float]:
        """
        Build extended feature dict for XGBoost training/inference.
        Returns all numeric features as flat dict.
        """
        dev = self.compute_deviation_features(event, user_id)
        hour = self._get_hour(event)
        ts = event.get('timestamp')
        dow = ts.weekday() if hasattr(ts, 'weekday') else int(event.get('day_of_week', 3))

        sf = session_features or {}

        all_features = {
            'hour_of_day': float(hour),
            'day_of_week': float(dow),
            'session_event_count': float(sf.get('session_event_count', 0)),
            'session_entropy': float(sf.get('session_entropy', 0)),
            'session_avg_rate': float(sf.get('session_avg_rate', 0)),
            'cumulative_risk': float(sf.get('cumulative_risk', 0)),
            'last_window_risk': float(sf.get('last_window_risk', 0)),
        }
        # Merge all deviation features
        all_features.update(dev)

        return all_features

    # --- Helpers ---

    def _get_hour(self, event: Dict) -> int:
        if '_hour_override' in event:
            return int(event['_hour_override'])
        ts = event.get('timestamp')
        if hasattr(ts, 'hour'):
            return ts.hour
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace('Z', '+00:00')).hour
            except Exception:
                pass
        h = event.get('hour')
        if h is not None:
            try:
                return int(h)
            except (ValueError, TypeError):
                pass
        return 12

    @staticmethod
    def _is_internal_ip(ip: str) -> bool:
        if not ip or ip == 'nan':
            return False
        return (ip.startswith('10.') or ip.startswith('192.168.') or
                ip.startswith('172.16.') or ip.startswith('172.17.') or
                ip.startswith('172.18.') or ip.startswith('172.19.') or
                ip.startswith('172.2') or ip.startswith('172.3'))


# Singleton
baseline_feature_builder = BaselineFeatureBuilder()
