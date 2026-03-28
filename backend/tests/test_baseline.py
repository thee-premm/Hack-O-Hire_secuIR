"""
Test suite for Redis Baseline Manager & Feature Builder
Run: cd backend && python tests/test_baseline.py
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import unittest
import numpy as np
from datetime import datetime
from collections import defaultdict


class TestRedisBaselineManager(unittest.TestCase):

    def setUp(self):
        from state.redis_baseline_manager import RedisBaselineManager
        self.mgr = RedisBaselineManager()

    def test_default_baseline_for_unknown_user(self):
        """Unknown user gets default baseline"""
        bl = self.mgr.get_baseline('unknown_user_xyz')
        self.assertIn(bl['type'], ['default', 'global'])
        self.assertIn('avg_login_hour', bl)

    def test_user_baseline_after_update(self):
        """User baseline reflects events"""
        uid = 'test_user_001'
        events = [
            {'timestamp': datetime(2026, 3, 28, 9, 0), 'event_type': 'login',
             'device_id': 'dev1', 'ip': '10.0.0.1', 'source': 'azure_ad',
             'severity': 'LOW', 'success': True},
            {'timestamp': datetime(2026, 3, 28, 10, 0), 'event_type': 'login',
             'device_id': 'dev1', 'ip': '10.0.0.1', 'source': 'azure_ad',
             'severity': 'LOW', 'success': True},
            {'timestamp': datetime(2026, 3, 28, 14, 0), 'event_type': 'transaction',
             'device_id': 'dev1', 'ip': '10.0.0.2', 'source': 'aws_cloudtrail',
             'severity': 'MEDIUM'},
        ]
        for ev in events:
            self.mgr.update_user_baseline(uid, ev)

        bl = self.mgr.get_baseline(uid)
        self.assertEqual(bl['type'], 'user')
        self.assertEqual(bl['event_count'], 3)
        self.assertIn('dev1', bl['devices'])

    def test_hierarchy_user_then_global(self):
        """Known user -> user baseline; unknown -> global"""
        uid = 'hierarchy_test_user'
        self.mgr.update_user_baseline(uid, {
            'timestamp': datetime(2026, 1, 1, 8, 0),
            'event_type': 'login', 'severity': 'LOW',
            'source': 'zeek', 'success': True,
        })

        user_bl = self.mgr.get_baseline(uid)
        self.assertEqual(user_bl['type'], 'user')

        new_bl = self.mgr.get_baseline('brand_new_999')
        self.assertIn(new_bl['type'], ['global', 'default'])

    def test_global_baseline_aggregates(self):
        """Global baseline has aggregate stats"""
        for i in range(5):
            self.mgr.update_user_baseline(f'glob_user_{i}', {
                'timestamp': datetime(2026, 1, 1, 10+i, 0),
                'event_type': 'login', 'severity': 'LOW', 'source': 'zeek',
            })

        gb = self.mgr.get_global_baseline()
        self.assertTrue(gb['exists'])
        self.assertGreater(gb['total_events'], 0)
        self.assertGreater(gb['unique_users'], 0)

    def test_baseline_features(self):
        """get_baseline_features returns expected keys"""
        uid = 'feat_test_user'
        self.mgr.update_user_baseline(uid, {
            'timestamp': datetime(2026, 1, 1, 9, 0),
            'event_type': 'login', 'severity': 'LOW',
            'device_id': 'known_dev', 'source': 'zeek',
        })

        feats = self.mgr.get_baseline_features(uid, {
            'timestamp': datetime(2026, 1, 1, 3, 0),  # unusual hour
            'device_id': 'unknown_dev',
            'event_type': 'login', 'severity': 'LOW',
        })

        self.assertIn('login_hour_deviation', feats)
        self.assertIn('device_match', feats)
        # 3am vs 9am baseline -> deviation should be positive
        self.assertGreater(feats['login_hour_deviation'], 0)
        # Unknown device -> no match
        self.assertEqual(feats['device_match'], 0.0)

    def test_null_user_skipped(self):
        """Null user IDs are handled gracefully"""
        self.mgr.update_user_baseline('', {'timestamp': datetime.now()})
        self.mgr.update_user_baseline(None, {'timestamp': datetime.now()})
        # Should not crash

    def test_stats(self):
        """Stats method returns expected structure"""
        stats = self.mgr.stats()
        self.assertIn('users_in_memory', stats)
        self.assertIn('global_events', stats)
        self.assertIn('redis_available', stats)


class TestBaselineFeatureBuilder(unittest.TestCase):

    def setUp(self):
        from features.baseline_feature_builder import BaselineFeatureBuilder
        self.builder = BaselineFeatureBuilder()

        # Seed some baseline data
        uid = 'feat_builder_user'
        from state.redis_baseline_manager import baseline_manager
        for h in [9, 10, 9, 11, 10]:
            baseline_manager.update_user_baseline(uid, {
                'timestamp': datetime(2026, 1, 1, h, 0),
                'event_type': 'login', 'severity': 'LOW',
                'host': 'WKS-01', 'ip': '10.0.0.1',
                'geo': 'US', 'source': 'azure_ad',
            })
        self.test_uid = uid

    def test_deviation_features_keys(self):
        """All expected feature keys present"""
        event = {
            'timestamp': datetime(2026, 1, 1, 3, 0),
            'event': 'Suspicious', 'severity': 'CRITICAL',
            'host': 'UNKNOWN', 'ip': '55.66.77.88',
            'source': 'sentinel_one',
            'message': 'Suspicious: user performed payment operation',
        }
        feats = self.builder.compute_deviation_features(event, self.test_uid)

        expected_keys = [
            'login_hour_deviation', 'device_match_score', 'location_match_score',
            'is_new_user', 'baseline_confidence', 'severity_score',
            'source_risk_score', 'is_high_risk_event', 'geo_risk',
            'ip_is_internal', 'attempts_norm', 'message_length_norm',
            'contains_sensitive_keyword', 'is_off_hours', 'is_weekend',
            'event_diversity_ratio',
        ]
        for k in expected_keys:
            self.assertIn(k, feats, f"Missing feature: {k}")
            self.assertIsInstance(feats[k], float, f"{k} not float")

    def test_suspicious_event_high_scores(self):
        """Suspicious event at unusual hour scores high risk features"""
        event = {
            'timestamp': datetime(2026, 1, 1, 3, 0),
            'event': 'Suspicious', 'severity': 'CRITICAL',
            'host': 'UNKNOWN', 'ip': '55.66.77.88',
            'source': 'sentinel_one',
            'message': 'Suspicious: user performed payment operation',
        }
        feats = self.builder.compute_deviation_features(event, self.test_uid)

        self.assertGreater(feats['login_hour_deviation'], 1.0)  # 3am vs ~10am
        self.assertEqual(feats['device_match_score'], 0.0)       # unknown host
        self.assertEqual(feats['severity_score'], 1.0)           # CRITICAL
        self.assertEqual(feats['is_high_risk_event'], 1.0)       # Suspicious
        self.assertEqual(feats['is_off_hours'], 1.0)             # 3am
        self.assertEqual(feats['ip_is_internal'], 0.0)           # public IP
        self.assertEqual(feats['contains_sensitive_keyword'], 1.0)  # "payment"

    def test_normal_event_low_scores(self):
        """Normal event at expected hour scores low risk"""
        event = {
            'timestamp': datetime(2026, 1, 1, 10, 0),
            'event': 'login', 'severity': 'LOW',
            'host': 'WKS-01', 'ip': '10.0.0.1',
            'source': 'azure_ad', 'geo': 'US',
            'message': 'User logged in successfully',
        }
        feats = self.builder.compute_deviation_features(event, self.test_uid)

        self.assertLess(feats['login_hour_deviation'], 1.0)      # normal hour
        self.assertEqual(feats['device_match_score'], 1.0)       # known device
        self.assertEqual(feats['location_match_score'], 1.0)     # known location
        self.assertEqual(feats['severity_score'], 0.1)           # LOW
        self.assertEqual(feats['ip_is_internal'], 1.0)           # 10.x.x.x

    def test_core_vector_shape(self):
        """Core vector has 11 elements"""
        event = {
            'timestamp': datetime(2026, 1, 1, 10, 0),
            'event': 'login', 'severity': 'LOW',
        }
        vec = self.builder.compute_core_vector(event, self.test_uid)
        self.assertEqual(vec.shape, (1, 11))

    def test_extended_vector_keys(self):
        """Extended vector has all features"""
        event = {
            'timestamp': datetime(2026, 1, 1, 10, 0),
            'event': 'login', 'severity': 'LOW',
            'source': 'zeek', 'ip': '10.0.0.1',
            'message': 'login: test_user logged in',
        }
        ext = self.builder.compute_extended_vector(event, self.test_uid)
        self.assertIn('hour_of_day', ext)
        self.assertIn('severity_score', ext)
        self.assertIn('is_high_risk_event', ext)
        self.assertGreater(len(ext), 15)  # at least 15 features

    def test_new_user_features(self):
        """New user gets is_new_user=1.0"""
        event = {
            'timestamp': datetime(2026, 1, 1, 10, 0),
            'event': 'login', 'severity': 'LOW',
        }
        feats = self.builder.compute_deviation_features(event, 'never_seen_user_xyz')
        self.assertEqual(feats['is_new_user'], 1.0)
        self.assertLess(feats['baseline_confidence'], 0.5)


if __name__ == '__main__':
    print("=" * 60)
    print("  BASELINE SYSTEM TEST SUITE")
    print("=" * 60)
    unittest.main(verbosity=2)
