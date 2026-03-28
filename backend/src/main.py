import pandas as pd
from pipeline import DetectionPipeline
import json

def main():
    # Initialize pipeline
    pipeline = DetectionPipeline()
    
    print("=" * 80)
    print("ENHANCED INCIDENT DETECTION & RESPONSE SYSTEM")
    print("=" * 80)
    
    # Test 1: Normal JSON log (existing format)
    print("\n[TEST 1] Processing normal JSON log...")
    normal_log = {
        "user_id": "cust_123",
        "user_type": "customer",
        "event_type": "transaction",
        "timestamp": "2026-03-28T14:23:17Z",
        "amount": 150.00,
        "payee_id": "payee_456",
        "success": True,
        "device_id": "device_abc",
        "ip_address": "192.168.1.100",
        "location_country": "US",
        "session_id": "sess_789"
    }
    result = pipeline.process_raw_log(normal_log)
    print(f"Result: {result.get('status')}")
    if 'decision' in result:
        print(f"  Action: {result['decision']['action_value']}")
        print(f"  Justification: {result['decision']['justification']}")
    
    # Test 2: CSV/JSON with different field names
    print("\n[TEST 2] Processing log with different field names...")
    different_fields = {
        "userId": "vip_999",
        "accountType": "vip",
        "action": "transfer",
        "time": "2026-03-28T15:30:00Z",
        "transactionValue": 50000.00,
        "recipient": "new_payee_001",
        "status": True,
        "deviceFingerprint": "unknown_device",
        "sourceIp": "45.33.22.11",
        "country": "NG",
        "sessionToken": "sess_attack"
    }
    result = pipeline.process_raw_log(different_fields)
    print(f"Result: {result.get('status')}")
    if 'decision' in result:
        print(f"  Action: {result['decision']['action_value']}")
        print(f"  Risk Score: {result['incident']['final_risk']:.3f}")
        print(f"  Justification: {result['decision']['justification']}")
    
    # Test 3: Duplicate detection
    print("\n[TEST 3] Testing duplicate detection...")
    duplicate_log = {
        "user_id": "cust_123",
        "event_type": "login",
        "timestamp": "2026-03-28T16:00:00Z",
        "success": False,
        "device_id": "device_abc",
        "ip_address": "192.168.1.100"
    }
    result1 = pipeline.process_raw_log(duplicate_log)
    result2 = pipeline.process_raw_log(duplicate_log)
    print(f"First duplicate check: {result1.get('status')}")
    print(f"Second duplicate check: {result2.get('status')}")
    
    # Test 4: Syslog format simulation
    print("\n[TEST 4] Processing syslog format...")
    syslog_format = {
        "host": "bank-server-01",
        "facility": "auth",
        "severity": "info",
        "message": "Login failed for user john_doe from IP 192.168.1.50",
        "timestamp": "Mar 28 17:45:22"
    }
    result = pipeline.process_raw_log(syslog_format, format_type='syslog')
    print(f"Result: {result.get('status')}")
    if 'decision' in result:
        print(f"  Normalized user_id: {result['incident']['user_id']}")
        print(f"  Action: {result['decision']['action_value']}")
    
    # Test 5: Playbook generation
    print("\n[TEST 5] Playbook generation...")
    high_risk_log = {
        "user_id": "vip_500",
        "account_tier": "vip",
        "event_type": "transaction",
        "timestamp": "2026-03-28T18:00:00Z",
        "amount": 100000.00,
        "payee_id": "unknown_payee_999",
        "payee_country": "RU",
        "is_new_payee": True,
        "device_id": "new_device_xyz",
        "location_country": "RU"
    }
    result = pipeline.process_raw_log(high_risk_log)
    if 'playbook' in result:
        print(f"  Playbook ID: {result['playbook']['playbook_id']}")
        print(f"  Requires Approval: {result['playbook']['requires_approval']}")
        print(f"  Approver: {result['playbook']['approval_required_from']}")
        print(f"  Action: {result['playbook']['recommended_actions'][0]['action']}")
        print(f"  Justification: {result['playbook']['justification']}")
    
    print("\n" + "=" * 80)
    print("DEMO COMPLETE")
    print("=" * 80)

if __name__ == '__main__':
    main()
