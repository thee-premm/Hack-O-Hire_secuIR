"""
API Endpoint Tests
Run: cd backend && python tests/test_api.py
Requires backend server to be running.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import requests
import json
import time
from datetime import datetime


BASE = "http://localhost:8000"


def test_root():
    r = requests.get(f"{BASE}/")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "operational"
    print("  [OK] GET / - operational")


def test_health():
    r = requests.get(f"{BASE}/api/health")
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "healthy"
    assert d["pipeline_loaded"] is True
    print("  [OK] GET /api/health - healthy")


def test_ingest_normal():
    event = {
        "raw_log": {
            "user_id": "api_test_user",
            "user_type": "customer",
            "event_type": "transaction",
            "timestamp": datetime.now().isoformat(),
            "amount": 50,
            "device_id": "known_device",
            "session_id": f"api_session_{time.time()}"
        }
    }
    r = requests.post(f"{BASE}/api/ingest", json=event)
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "processed"
    assert d["decision"]["action_value"] == "LOG_ONLY"
    print(f"  [OK] POST /api/ingest - normal -> LOG_ONLY")


def test_ingest_suspicious():
    event = {
        "raw_log": {
            "user_id": "api_test_user",
            "user_type": "customer",
            "event_type": "transaction",
            "timestamp": datetime.now().isoformat(),
            "amount": 50000,
            "is_new_payee": True,
            "payee_country": "RU",
            "device_id": "unknown_device",
            "location_country": "RU",
            "session_id": f"api_session_sus_{time.time()}"
        }
    }
    r = requests.post(f"{BASE}/api/ingest", json=event)
    assert r.status_code == 200
    d = r.json()
    assert d["status"] == "processed"
    assert d["decision"]["action_value"] != "LOG_ONLY"
    print(f"  [OK] POST /api/ingest - suspicious -> {d['decision']['action_value']}")


def test_incidents():
    r = requests.get(f"{BASE}/api/incidents")
    assert r.status_code == 200
    d = r.json()
    assert "incidents" in d
    assert "total" in d
    print(f"  [OK] GET /api/incidents - {d['total']} incidents")


def test_stats():
    r = requests.get(f"{BASE}/api/stats")
    assert r.status_code == 200
    d = r.json()
    assert "total_incidents" in d
    assert "risk_distribution" in d
    assert "actions" in d
    print(f"  [OK] GET /api/stats - {d['total_incidents']} total")


def test_simulate():
    r = requests.post(f"{BASE}/api/simulate?count=3")
    assert r.status_code == 200
    d = r.json()
    assert d["simulated"] == 3
    print(f"  [OK] POST /api/simulate - {d['simulated']} generated")


def test_ingest_batch():
    events = [
        {"raw_log": {"user_id": f"batch_{i}", "event_type": "login",
                     "timestamp": datetime.now().isoformat(),
                     "session_id": f"batch_sess_{i}_{time.time()}"}}
        for i in range(3)
    ]
    r = requests.post(f"{BASE}/api/ingest-batch", json=events)
    assert r.status_code == 200
    d = r.json()
    assert len(d["results"]) == 3
    print(f"  [OK] POST /api/ingest-batch - {len(d['results'])} processed")


if __name__ == "__main__":
    print("=" * 60)
    print("  API ENDPOINT TESTS")
    print("=" * 60)

    tests = [
        test_root, test_health, test_ingest_normal, test_ingest_suspicious,
        test_incidents, test_stats, test_simulate, test_ingest_batch,
    ]

    passed = 0
    failed = 0
    for fn in tests:
        try:
            fn()
            passed += 1
        except Exception as e:
            print(f"  [FAIL] {fn.__name__}: {e}")
            failed += 1

    print(f"\n  Results: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)
