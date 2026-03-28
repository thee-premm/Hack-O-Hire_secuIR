"""
Test the complete Response Engine (enrichment + rules + policies + audit)
Run: cd backend && python tests/test_response_engine.py
"""

import os, sys, json

_TESTS = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_TESTS)
_SRC = os.path.join(_BACKEND, 'src')
sys.path.insert(0, _SRC)

from response.engine import ResponseEngine, Action
from response.bands import BandEnricher
from response.policies import PolicyEngine
from response.audit import AuditLogger


def _sep(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")


def test_band_enrichment():
    """Test that BandEnricher adds all expected band fields."""
    _sep("TEST 1: Band Enrichment")
    enricher = BandEnricher()

    incident = {
        'final_risk': 0.85,
        'amount': 25000,
        'device_match_score': 0,
        'location_deviation_km': 3000,
        'country_risk': 0.9,
        'core_features': {
            'hour_of_day': 3,
            'session_avg_rate': 120,
            'session_entropy': 3.0,
        },
    }

    enriched = enricher.enrich(incident)

    checks = [
        ('risk_band',          'HIGH'),
        ('amount_band',        'HIGH'),
        ('device_band',        'NEW'),
        ('login_hour_band',    'UNUSUAL'),
        ('request_rate_band',  'BOT_LIKE'),
        ('api_diversity_band', 'SCRAPING'),
        ('country_risk_band',  'CRITICAL'),
    ]
    ok = True
    for field, expected in checks:
        actual = enriched.get(field)
        status = '[OK]' if actual == expected else '[FAIL]'
        if actual != expected:
            ok = False
        print(f"  {status}  {field:25s} = {actual:15s} (expected {expected})")

    assert 'behavioral_context' in enriched, "behavioral_context missing"
    print(f"  [OK]  behavioral_context present with {len(enriched['behavioral_context'])} keys")
    return ok


def test_rule_engine():
    """Test that rules fire in correct priority order."""
    _sep("TEST 2: Rule Engine Priority")
    engine = ResponseEngine()

    scenarios = [
        ("Critical risk -> BLOCK",  {'final_risk': 0.95}, {},                          'critical_risk_block'),
        ("VIP high risk -> REVIEW", {'final_risk': 0.85}, {'tier': 'vip'},             'vip_high_risk_review'),
        ("Insider threat -> FREEZE",{'incident_type': 'insider_threat', 'final_risk': 0.6},
                                                          {'user_type': 'employee'},   'insider_threat_detected'),
        ("Medium risk -> MFA",      {'final_risk': 0.65}, {},                          'medium_risk_mfa'),
        ("Low risk -> LOG_ONLY",    {'final_risk': 0.1},  {},                          'default_log_only'),
    ]

    ok = True
    for label, inc, ctx, expected_rule in scenarios:
        decision = engine.decide(inc, ctx)
        actual = decision['rule_name']
        status = '[OK]' if actual == expected_rule else '[FAIL]'
        if actual != expected_rule:
            ok = False
        print(f"  {status}  {label:40s} -> {actual}")
    return ok


def test_policy_overrides():
    """Test that policies modify actions correctly."""
    _sep("TEST 3: Policy Overrides")
    policy_engine = PolicyEngine()

    # VIP should not be blocked -> replaced with DELAY + NOTIFY_MANAGER
    result = policy_engine.apply(
        incident={'incident_type': 'fraud'},
        user_context={'tier': 'vip'},
        primary_actions=[Action.BLOCK_TRANSACTION],
        requires_approval=False,
    )

    ok = True
    if Action.BLOCK_TRANSACTION in result['actions']:
        print("  [FAIL]  VIP still has BLOCK_TRANSACTION")
        ok = False
    else:
        print("  [OK]  VIP auto-block removed")

    if 'vip_no_auto_block' in result['applied_policies']:
        print(f"  [OK]  Policy applied: vip_no_auto_block")
    else:
        print(f"  [FAIL]  Policy not applied")
        ok = False

    if 'security_manager' in result['additional_notify']:
        print(f"  [OK]  security_manager notified")
    else:
        print(f"  [FAIL]  security_manager not in notify list")
        ok = False

    # Insider threat for employee -> HR notified
    result2 = policy_engine.apply(
        incident={'incident_type': 'insider_threat'},
        user_context={'user_type': 'employee'},
        primary_actions=[Action.FREEZE_ACCOUNT],
        requires_approval=True,
    )
    if 'insider_threat_hr' in result2['applied_policies']:
        print(f"  [OK]  Insider threat -> HR notified: {result2['additional_notify']}")
    else:
        print(f"  [FAIL]  Insider HR policy not applied")
        ok = False

    return ok


def test_is_threat_field():
    """Test is_threat boolean in decision."""
    _sep("TEST 4: is_threat Field")
    engine = ResponseEngine()

    ok = True
    for risk, expected in [(0.3, False), (0.5, False), (0.7, False), (0.71, True), (0.95, True)]:
        d = engine.decide({'final_risk': risk}, {})
        actual = d['is_threat']
        status = '[OK]' if actual == expected else '[FAIL]'
        if actual != expected:
            ok = False
        print(f"  {status}  risk={risk:.2f} -> is_threat={actual}")
    return ok


def test_full_process():
    """Test the full process() orchestration."""
    _sep("TEST 5: Full process() Pipeline")
    engine = ResponseEngine()

    incident = {
        'incident_id': 'test_001',
        'timestamp': '2026-03-29T10:00:00Z',
        'user_id': 'user_vip_1',
        'user_type': 'customer',
        'user_tier': 'VIP',
        'event_type': 'transaction',
        'final_risk': 0.88,
        'incident_type': 'account_takeover',
        'amount': 5000,
        'device_match_score': 0,
        'location_deviation_km': 4000,
        'country_risk': 0.85,
        'core_features': {
            'hour_of_day': 2,
            'session_avg_rate': 10,
            'session_entropy': 0.5,
        },
    }
    user_context = {'user_id': 'user_vip_1', 'tier': 'vip', 'user_type': 'customer'}

    result = engine.process(incident, user_context)

    ok = True

    # Check structure
    for key in ['status', 'incident', 'decision', 'playbook']:
        if key not in result:
            print(f"  [FAIL]  Missing key: {key}")
            ok = False
        else:
            print(f"  [OK]  Key present: {key}")

    dec = result['decision']

    # Should have enrichment bands
    enriched = result['incident']
    if enriched.get('risk_band'):
        print(f"  [OK]  risk_band = {enriched['risk_band']}")
    else:
        print(f"  [FAIL]  risk_band missing from enriched incident")
        ok = False

    # is_threat should be True (risk 0.88 > 0.7)
    if dec.get('is_threat') is True:
        print(f"  [OK]  is_threat = True (risk {dec['risk_score']})")
    else:
        print(f"  [FAIL]  is_threat should be True, got {dec.get('is_threat')}")
        ok = False

    # Policies applied
    print(f"  [OK]  Policies applied: {dec.get('policies_applied', [])}")
    print(f"  [OK]  Actions: {dec.get('actions', [])}")
    print(f"  [OK]  Notifications: {dec.get('additional_notifications', [])}")

    # Playbook
    pb = result.get('playbook', {})
    if pb.get('playbook_id'):
        print(f"  [OK]  Playbook ID: {pb['playbook_id']}")
    else:
        print(f"  [FAIL]  Playbook missing ID")
        ok = False

    return ok


def test_audit_logging():
    """Test audit log file creation."""
    _sep("TEST 6: Audit Logging")
    import tempfile
    log_dir = os.path.join(_BACKEND, 'logs', 'audit')
    audit = AuditLogger(log_dir)

    audit.log(
        incident={'incident_id': 'audit_test', 'final_risk': 0.9, 'risk_band': 'CRITICAL'},
        decision={'rule_name': 'test_rule', 'is_threat': True},
        final_actions=[Action.BLOCK_TRANSACTION],
        playbook={'playbook_id': 'PB_TEST'},
        user_context={'tier': 'standard', 'password': 'secret123'},
    )

    # Check file exists
    from datetime import datetime as dt
    today = dt.now().strftime('%Y%m%d')
    path = os.path.join(log_dir, f'audit_{today}.jsonl')
    ok = True
    if os.path.exists(path):
        print(f"  [OK]  Audit file created: {path}")
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        last = json.loads(lines[-1])
        if last.get('incident_id') == 'audit_test':
            print(f"  [OK]  Audit entry written correctly")
        # Check sanitization
        if last.get('user_context', {}).get('password') == '[REDACTED]':
            print(f"  [OK]  Sensitive fields redacted")
        else:
            print(f"  [FAIL]  Password not redacted: {last.get('user_context', {}).get('password')}")
            ok = False
    else:
        print(f"  [FAIL]  Audit file not found")
        ok = False
    return ok


def main():
    print("=" * 70)
    print("  SECUIR RESPONSE ENGINE TEST SUITE")
    print("=" * 70)

    tests = [
        ("Band Enrichment", test_band_enrichment),
        ("Rule Engine", test_rule_engine),
        ("Policy Overrides", test_policy_overrides),
        ("is_threat Field", test_is_threat_field),
        ("Full process()", test_full_process),
        ("Audit Logging", test_audit_logging),
    ]

    results = []
    for name, fn in tests:
        try:
            passed = fn()
            results.append((name, passed))
        except Exception as e:
            print(f"  [ERROR]  {e}")
            results.append((name, False))

    _sep("SUMMARY")
    all_pass = True
    for name, passed in results:
        status = '[OK]  ' if passed else '[FAIL]'
        if not passed:
            all_pass = False
        print(f"  {status} {name}")

    total = len(results)
    passed_count = sum(1 for _, p in results if p)
    print(f"\n  Total: {passed_count}/{total} passed")

    if all_pass:
        print("\n  ALL RESPONSE ENGINE TESTS PASSED.")
    else:
        print("\n  SOME TESTS FAILED.")

    return all_pass


if __name__ == '__main__':
    ok = main()
    sys.exit(0 if ok else 1)
