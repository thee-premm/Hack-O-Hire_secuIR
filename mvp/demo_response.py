from response.engine import ResponseEngine
from response.playbook import PlaybookGenerator
import json

def demo():
    print("=" * 80)
    print("RESPONSE ENGINE DEMO")
    print("=" * 80)
    
    engine = ResponseEngine()
    playbook_gen = PlaybookGenerator()
    
    # Test scenarios
    scenarios = [
        {
            'name': 'Critical Risk Transaction',
            'incident': {'incident_id': 'inc_001', 'user_id': 'user_123', 'final_risk': 0.95, 'event_type': 'transaction'},
            'user_context': {'tier': 'basic', 'user_type': 'customer'}
        },
        {
            'name': 'VIP High Risk',
            'incident': {'incident_id': 'inc_002', 'user_id': 'vip_456', 'final_risk': 0.85, 'event_type': 'transaction'},
            'user_context': {'tier': 'vip', 'user_type': 'customer'}
        },
        {
            'name': 'Insider Threat',
            'incident': {'incident_id': 'inc_003', 'user_id': 'emp_789', 'final_risk': 0.75, 'incident_type': 'insider_threat'},
            'user_context': {'tier': 'basic', 'user_type': 'employee'}
        },
        {
            'name': 'New Payee High Risk',
            'incident': {'incident_id': 'inc_004', 'user_id': 'user_123', 'final_risk': 0.65, 'is_new_payee': True, 'country_risk': 0.8},
            'user_context': {'tier': 'basic', 'user_type': 'customer'}
        },
        {
            'name': 'Medium Risk Activity',
            'incident': {'incident_id': 'inc_005', 'user_id': 'user_555', 'final_risk': 0.6, 'event_type': 'login'},
            'user_context': {'tier': 'basic', 'user_type': 'customer'}
        },
        {
            'name': 'Benign Activity',
            'incident': {'incident_id': 'inc_006', 'user_id': 'user_666', 'final_risk': 0.1, 'event_type': 'login'},
            'user_context': {'tier': 'basic', 'user_type': 'customer'}
        }
    ]
    
    for scenario in scenarios:
        print(f"\n{'='*60}")
        print(f"Scenario: {scenario['name']}")
        print(f"{'='*60}")
        
        decision = engine.decide(scenario['incident'], scenario['user_context'])
        
        print(f"Action: {decision['action_value']}")
        print(f"Requires Approval: {decision['requires_approval']}")
        print(f"Justification: {decision['justification']}")
        print(f"Rule Triggered: {decision['rule_name']} (priority {decision['rule_priority']})")
        
        # Generate playbook
        evidence = {
            'core_features': {'risk': scenario['incident'].get('final_risk')},
            'model_outputs': {'final_risk': scenario['incident'].get('final_risk')}
        }
        playbook = playbook_gen.generate(scenario['incident'], decision, evidence)
        
        print(f"\nPlaybook Generated: {playbook['playbook_id']}")
        print(f"  Status: {playbook['status']}")
        print(f"  Approver: {playbook['approval_workflow']['approver']}")
        print(f"  Estimated Response: {playbook['approval_workflow']['estimated_response_time']}")
        print(f"  Investigation Steps: {len(playbook['investigation_steps'])}")
        print(f"  Recommendations: {len(playbook['recommendations'])}")
    
    print("\n" + "=" * 80)
    print("Rule Statistics:")
    print(json.dumps(engine.get_rule_statistics(), indent=2))
    print(f"\nTotal decisions tracked: {len(engine.get_decision_history())}")
    print("=" * 80)

if __name__ == '__main__':
    demo()
