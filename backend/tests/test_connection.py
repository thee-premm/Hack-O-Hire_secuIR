"""
Backend-Frontend Connection Test
Run: cd backend && python tests/test_connection.py
Requires both servers to be running.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import requests
import json
from datetime import datetime


def test_backend_health():
    """Test if backend API is running"""
    try:
        r = requests.get("http://localhost:8000/", timeout=5)
        data = r.json()
        print(f"  [OK] Backend is running: {r.status_code}")
        print(f"       Name: {data.get('name')}")
        print(f"       Version: {data.get('version')}")
        return True
    except Exception as e:
        print(f"  [FAIL] Backend not reachable: {e}")
        return False


def test_api_health():
    """Test health endpoint"""
    try:
        r = requests.get("http://localhost:8000/api/health", timeout=5)
        data = r.json()
        print(f"  [OK] Health check: {data.get('status')}")
        print(f"       Pipeline: {'loaded' if data.get('pipeline_loaded') else 'not loaded'}")
        print(f"       Incidents tracked: {data.get('incidents_tracked')}")
        return True
    except Exception as e:
        print(f"  [FAIL] Health check failed: {e}")
        return False


def test_api_ingest():
    """Test ingestion endpoint"""
    event = {
        "raw_log": {
            "user_id": "connection_test",
            "user_type": "customer",
            "event_type": "transaction",
            "timestamp": datetime.now().isoformat(),
            "amount": 100,
            "device_id": "test_device",
            "session_id": "conn_test_session"
        },
        "format_type": "json"
    }
    try:
        r = requests.post("http://localhost:8000/api/ingest", json=event, timeout=10)
        data = r.json()
        print(f"  [OK] Ingest: {r.status_code}")
        print(f"       Status: {data.get('status')}")
        print(f"       Action: {data.get('decision', {}).get('action_value', 'N/A')}")
        return True
    except Exception as e:
        print(f"  [FAIL] Ingest failed: {e}")
        return False


def test_api_stats():
    """Test stats endpoint"""
    try:
        r = requests.get("http://localhost:8000/api/stats", timeout=5)
        data = r.json()
        print(f"  [OK] Stats: {r.status_code}")
        print(f"       Total incidents: {data.get('total_incidents')}")
        print(f"       Risk distribution: {data.get('risk_distribution')}")
        return True
    except Exception as e:
        print(f"  [FAIL] Stats failed: {e}")
        return False


def test_api_simulate():
    """Test simulation endpoint"""
    try:
        r = requests.post("http://localhost:8000/api/simulate?count=5", timeout=15)
        data = r.json()
        print(f"  [OK] Simulate: {r.status_code}")
        print(f"       Generated: {data.get('simulated')} events")
        return True
    except Exception as e:
        print(f"  [FAIL] Simulate failed: {e}")
        return False


def test_frontend_connection():
    """Test if frontend dev server is reachable"""
    try:
        r = requests.get("http://localhost:5173", timeout=5)
        print(f"  [OK] Frontend is running: {r.status_code}")
        return True
    except Exception:
        try:
            r = requests.get("http://localhost:3000", timeout=5)
            print(f"  [OK] Frontend is running on port 3000: {r.status_code}")
            return True
        except Exception as e:
            print(f"  [FAIL] Frontend not reachable: {e}")
            return False


if __name__ == "__main__":
    print("=" * 60)
    print("  BACKEND-FRONTEND CONNECTION TEST")
    print("=" * 60)

    tests = [
        ("Backend Root", test_backend_health),
        ("Health Check", test_api_health),
        ("Ingest API", test_api_ingest),
        ("Stats API", test_api_stats),
        ("Simulate API", test_api_simulate),
        ("Frontend", test_frontend_connection),
    ]

    results = []
    for name, fn in tests:
        print(f"\n[{name}]")
        results.append((name, fn()))

    print("\n" + "=" * 60)
    print("  SUMMARY")
    print("=" * 60)
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  {'[OK]' if ok else '[FAIL]':8s} {name}")
    print(f"\n  {passed}/{len(results)} passed")

    if passed == len(results):
        print("\n  ALL CONNECTIONS VERIFIED!")
        print("  Open http://localhost:5173 to view the dashboard")
    else:
        print("\n  Some connections failed. Please check:")
        print("  1. Backend: cd backend && python src/api_server.py")
        print("  2. Frontend: cd frontend && npm run dev")

    sys.exit(0 if passed == len(results) else 1)
