import unittest
from response.engine import ResponseEngine, Action
from response.playbook import PlaybookGenerator

class TestResponseEngine(unittest.TestCase):
    
    def setUp(self):
        self.engine = ResponseEngine()
        self.playbook_gen = PlaybookGenerator()
    
    def test_critical_risk_block(self):
        """Test critical risk triggers block"""
        incident = {'final_risk': 0.95}
        user_context = {'tier': 'basic'}
        decision = self.engine.decide(incident, user_context)
        self.assertEqual(decision['action'], Action.BLOCK_TRANSACTION)
        self.assertFalse(decision['requires_approval'])
    
    def test_vip_protection(self):
        """Test VIP never auto-blocked"""
        incident = {'final_risk': 0.95}
        user_context = {'tier': 'vip'}
        decision = self.engine.decide(incident, user_context)
        self.assertEqual(decision['action'], Action.MANUAL_REVIEW)
        self.assertTrue(decision['requires_approval'])
    
    def test_medium_risk_mfa(self):
        """Test medium risk triggers MFA"""
        incident = {'final_risk': 0.6}
        user_context = {'tier': 'basic'}
        decision = self.engine.decide(incident, user_context)
        self.assertEqual(decision['action'], Action.MFA_CHALLENGE)
    
    def test_insider_threat(self):
        """Test insider threat handling"""
        incident = {
            'final_risk': 0.7,
            'incident_type': 'insider_threat'
        }
        user_context = {'user_type': 'employee', 'tier': 'basic'}
        decision = self.engine.decide(incident, user_context)
        self.assertEqual(decision['action'], Action.FREEZE_ACCOUNT)
        self.assertTrue(decision['requires_approval'])
    
    def test_playbook_generation(self):
        """Test playbook generation"""
        incident = {
            'incident_id': 'test_123',
            'user_id': 'test_user',
            'user_type': 'customer',
            'final_risk': 0.85,
            'micro_risk': 0.8,
            'anomaly_score': 0.7,
            'event_type': 'transaction'
        }
        decision = {
            'action_value': 'BLOCK_TRANSACTION',
            'justification': 'Critical risk',
            'rule_name': 'critical_risk_block',
            'requires_approval': False
        }
        evidence = {
            'core_features': {'hour': 14, 'risk': 0.85},
            'model_outputs': {'micro_risk': 0.8}
        }
        
        playbook = self.playbook_gen.generate(incident, decision, evidence)
        
        self.assertIsNotNone(playbook['playbook_id'])
        self.assertEqual(playbook['decision']['action'], 'BLOCK_TRANSACTION')
        self.assertEqual(playbook['status'], 'auto_executed')
        self.assertGreater(len(playbook['investigation_steps']), 0)
    
    def test_rule_priority(self):
        """Test rules are evaluated in priority order"""
        incident = {'final_risk': 0.95, 'incident_type': 'account_takeover'}
        user_context = {'tier': 'basic'}
        decision = self.engine.decide(incident, user_context)
        # Should match critical_risk_block (priority 100) before account_takeover (200)
        self.assertEqual(decision['action'], Action.BLOCK_TRANSACTION)
    
    def test_default_log_only(self):
        """Test benign event gets LOG_ONLY"""
        incident = {'final_risk': 0.1}
        user_context = {'tier': 'basic'}
        decision = self.engine.decide(incident, user_context)
        self.assertEqual(decision['action'], Action.LOG_ONLY)
        self.assertFalse(decision['requires_approval'])
    
    def test_new_payee_high_risk(self):
        """Test high risk new payee triggers delay"""
        incident = {'final_risk': 0.65, 'is_new_payee': True, 'country_risk': 0.8}
        user_context = {'tier': 'basic'}
        decision = self.engine.decide(incident, user_context)
        self.assertEqual(decision['action'], Action.DELAY_TRANSACTION)
    
    def test_decision_history(self):
        """Test audit trail is maintained"""
        incident = {'final_risk': 0.5}
        user_context = {'tier': 'basic'}
        self.engine.decide(incident, user_context)
        history = self.engine.get_decision_history()
        self.assertGreater(len(history), 0)
    
    def test_rule_statistics(self):
        """Test rule statistics tracking"""
        self.engine.decide({'final_risk': 0.95}, {'tier': 'basic'})
        self.engine.decide({'final_risk': 0.1}, {'tier': 'basic'})
        stats = self.engine.get_rule_statistics()
        self.assertIn('critical_risk_block', stats)
        self.assertIn('default_log_only', stats)
    
    def test_playbook_approval_workflow(self):
        """Test playbook determines correct approver"""
        # Employee incident -> security_team_and_hr
        incident = {'user_type': 'employee', 'final_risk': 0.8}
        decision = {'requires_approval': True, 'action_value': 'FREEZE_ACCOUNT'}
        evidence = {'core_features': {}}
        playbook = self.playbook_gen.generate(incident, decision, evidence)
        self.assertEqual(playbook['approval_workflow']['approver'], 'security_team_and_hr')
        
        # VIP incident -> security_manager
        incident_vip = {'user_tier': 'vip', 'user_type': 'customer', 'final_risk': 0.9}
        decision_vip = {'requires_approval': True, 'action_value': 'MANUAL_REVIEW'}
        playbook_vip = self.playbook_gen.generate(incident_vip, decision_vip, evidence)
        self.assertEqual(playbook_vip['approval_workflow']['approver'], 'security_manager')
    
    def test_playbook_recommendations(self):
        """Test recommendations are generated"""
        incident = {'final_risk': 0.9, 'is_new_payee': True, 'device_match_score': 0}
        decision = {'action_value': 'BLOCK_TRANSACTION'}
        evidence = {}
        playbook = self.playbook_gen.generate(incident, decision, evidence)
        self.assertGreater(len(playbook['recommendations']), 1)

if __name__ == '__main__':
    unittest.main()
