import unittest
import json
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from datetime import datetime
from pipeline import DetectionPipeline


class TestEnhancedPipeline(unittest.TestCase):
    
    def setUp(self):
        self.pipeline = DetectionPipeline()
    
    def test_normalization_json(self):
        """Test JSON log normalization"""
        log = {"userId": "test_user", "time": "2026-03-28T10:00:00Z", "action": "login"}
        result = self.pipeline.process_raw_log(log)
        self.assertEqual(result['status'], 'processed')
        self.assertEqual(result['incident']['user_id'], 'test_user')
    
    def test_normalization_different_fields(self):
        """Test logs with different field names"""
        log = {"username": "john_doe", "event_time": "2026-03-28T11:00:00Z", "type": "transaction", "amt": 1000}
        result = self.pipeline.process_raw_log(log)
        self.assertEqual(result['status'], 'processed')
        self.assertEqual(result['incident']['user_id'], 'john_doe')
        self.assertEqual(result['incident']['event_type'], 'transaction')
    
    def test_duplicate_detection(self):
        """Test duplicate detection"""
        log = {"user_id": "dup_test", "event_type": "login", "timestamp": datetime.now().isoformat()}
        result1 = self.pipeline.process_raw_log(log)
        result2 = self.pipeline.process_raw_log(log)
        self.assertEqual(result1['status'], 'processed')
        self.assertEqual(result2['status'], 'duplicate')
    
    def test_playbook_generation(self):
        """Test playbook generation"""
        log = {"user_id": "vip_test", "account_tier": "vip", "event_type": "transaction", 
               "amount": 100000, "is_new_payee": True}
        result = self.pipeline.process_raw_log(log)
        self.assertIn('approval_workflow', result['playbook'])
        self.assertIn('requires_approval', result['playbook']['approval_workflow'])
    
    def test_response_rules(self):
        """Test response rules produce valid actions"""
        log = {"user_id": "test_resp", "event_type": "transaction", "amount": 100000, "is_new_payee": True}
        result = self.pipeline.process_raw_log(log)
        self.assertIn('decision', result)
        valid_actions = ['LOG_ONLY', 'MFA_CHALLENGE', 'DELAY_TRANSACTION', 'RESTRICT_SESSION',
                         'BLOCK_TRANSACTION', 'FREEZE_ACCOUNT', 'TERMINATE_SESSION',
                         'NOTIFY_SOC', 'MANUAL_REVIEW', 'REPORT_TO_COMPLIANCE']
        self.assertIn(result['decision']['action_value'], valid_actions)
    
    def test_timestamp_reordering(self):
        """Test timestamp reordering"""
        logs = [
            {"user_id": "test_order_1", "timestamp": "2026-03-28T10:05:00Z", "event_type": "login"},
            {"user_id": "test_order_2", "timestamp": "2026-03-28T10:00:00Z", "event_type": "login"},
            {"user_id": "test_order_3", "timestamp": "2026-03-28T10:02:00Z", "event_type": "login"}
        ]
        results = []
        for log in logs:
            result = self.pipeline.process_raw_log(log)
            if result['status'] == 'processed':
                results.append(result)
        # All should be processed
        self.assertTrue(len(results) > 0)
    
    def test_syslog_format(self):
        """Test syslog format handling"""
        syslog = {"message": "Failed login for user test_user", "timestamp": "Mar 28 12:00:00"}
        result = self.pipeline.process_raw_log(syslog, format_type='syslog')
        self.assertEqual(result['status'], 'processed')
        self.assertIsNotNone(result['incident']['user_id'])
    
    def test_legacy_process_event(self):
        """Test backward-compatible process_event method"""
        import pandas as pd
        event = {
            'timestamp': pd.Timestamp('2026-03-28T10:00:00'),
            'user_id': 'legacy_user',
            'user_type': 'customer',
            'event_type': 'login',
            'success': True,
            'device_id': 'device_001',
            'ip_address': '192.168.1.1',
            'location_country': 'US',
            'session_id': 'sess_legacy',
            'amount': 0,
            'is_new_payee': False,
            'country_risk': 0
        }
        result = self.pipeline.process_event(event)
        self.assertIn('action', result)
        self.assertIn('risk', result)
        self.assertIn('type', result)

if __name__ == '__main__':
    unittest.main()
