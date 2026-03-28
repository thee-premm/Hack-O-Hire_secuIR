"""
FastAPI server for the Banking Security Detection System
Run with: uvicorn api_server:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import json
import uuid
import random
import asyncio
from collections import deque

# Import existing pipeline
from pipeline import DetectionPipeline
from response.engine import ResponseEngine, Action

# Initialize FastAPI
app = FastAPI(title="Banking Security Detection System", version="2.0.0")

# CORS for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize pipeline
pipeline = DetectionPipeline()
response_engine = ResponseEngine()

# In-memory stores
incidents_history = deque(maxlen=500)
event_stream = deque(maxlen=1000)


# ============================================================
# WebSocket Manager
# ============================================================
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


# ============================================================
# Pydantic Models
# ============================================================
class LogEvent(BaseModel):
    raw_log: Dict[str, Any]
    format_type: str = "json"


# ============================================================
# Helper: serialize incident for JSON response
# ============================================================
def _serialize_result(result: dict) -> dict:
    """Make pipeline result JSON-serializable"""
    import copy
    out = copy.deepcopy(result)

    def _fix(obj):
        if isinstance(obj, dict):
            return {k: _fix(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [_fix(v) for v in obj]
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        if hasattr(obj, 'value'):  # Enum
            return obj.value
        try:
            json.dumps(obj)
            return obj
        except (TypeError, ValueError):
            return str(obj)

    return _fix(out)


# ============================================================
# API Endpoints
# ============================================================

@app.get("/")
async def root():
    return {
        "name": "Banking Security Detection System",
        "version": "2.0.0",
        "status": "operational",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/api/ingest")
async def ingest_log(event: LogEvent):
    """Ingest a single log event"""
    try:
        result = pipeline.process_raw_log(event.raw_log, event.format_type)
        safe = _serialize_result(result)

        if result.get('status') == 'processed':
            record = {
                'timestamp': datetime.now().isoformat(),
                'incident': safe.get('incident'),
                'decision': safe.get('decision'),
                'playbook': safe.get('playbook'),
                'playbook_summary': {
                    'id': safe.get('playbook', {}).get('playbook_id'),
                    'action': safe.get('decision', {}).get('action_value'),
                    'risk': safe.get('incident', {}).get('final_risk', 0),
                    'requires_approval': safe.get('decision', {}).get('requires_approval', False),
                    'justification': safe.get('decision', {}).get('justification', ''),
                }
            }
            incidents_history.append(record)

            await manager.broadcast({
                'type': 'new_incident',
                'data': {
                    'incident_id': safe.get('incident', {}).get('incident_id'),
                    'user_id': safe.get('incident', {}).get('user_id'),
                    'risk': safe.get('incident', {}).get('final_risk', 0),
                    'action': safe.get('decision', {}).get('action_value'),
                    'timestamp': datetime.now().isoformat()
                }
            })

        return safe
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/ingest-batch")
async def ingest_batch(events: List[LogEvent]):
    """Ingest multiple log events"""
    results = []
    for event in events:
        try:
            result = pipeline.process_raw_log(event.raw_log, event.format_type)
            safe = _serialize_result(result)
            if result.get('status') == 'processed':
                incidents_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'incident': safe.get('incident'),
                    'decision': safe.get('decision'),
                    'playbook': safe.get('playbook'),
                    'playbook_summary': {
                        'id': safe.get('playbook', {}).get('playbook_id'),
                        'action': safe.get('decision', {}).get('action_value'),
                        'risk': safe.get('incident', {}).get('final_risk', 0),
                    }
                })
            results.append(safe)
        except Exception as e:
            results.append({'status': 'error', 'error': str(e)})
    return {"results": results}


@app.get("/api/incidents")
async def get_incidents(limit: int = 50, risk_min: Optional[float] = None):
    """Get recent incidents"""
    incidents = list(incidents_history)[-limit:]
    if risk_min is not None:
        incidents = [i for i in incidents
                     if i.get('playbook_summary', {}).get('risk', 0) >= risk_min]
    return {
        "incidents": incidents,
        "total": len(incidents),
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/incidents/{incident_id}")
async def get_incident_detail(incident_id: str):
    """Get detailed incident information"""
    for inc in incidents_history:
        if inc.get('incident', {}).get('incident_id') == incident_id:
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")


@app.get("/api/playbook/{incident_id}")
async def get_playbook(incident_id: str):
    """Get playbook for specific incident"""
    for inc in incidents_history:
        if inc.get('incident', {}).get('incident_id') == incident_id:
            return inc.get('playbook', {})
    raise HTTPException(status_code=404, detail="Playbook not found")


@app.get("/api/stats")
async def get_stats():
    """Get system statistics"""
    incidents = list(incidents_history)
    total = len(incidents)
    high = len([i for i in incidents if i.get('playbook_summary', {}).get('risk', 0) > 0.7])
    medium = len([i for i in incidents if 0.4 < i.get('playbook_summary', {}).get('risk', 0) <= 0.7])
    low = len([i for i in incidents if i.get('playbook_summary', {}).get('risk', 0) <= 0.4])

    actions = {}
    for inc in incidents:
        action = inc.get('playbook_summary', {}).get('action', 'UNKNOWN')
        actions[action] = actions.get(action, 0) + 1

    rule_stats = response_engine.get_rule_statistics()

    return {
        "total_incidents": total,
        "risk_distribution": {"high": high, "medium": medium, "low": low},
        "actions": actions,
        "rule_triggers": rule_stats,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "pipeline_loaded": pipeline is not None,
        "incidents_tracked": len(incidents_history),
        "timestamp": datetime.now().isoformat()
    }


# ============================================================
# Simulation endpoint (generates fake traffic for demo)
# ============================================================
@app.post("/api/simulate")
async def simulate_traffic(count: int = 10):
    """Generate simulated events for demo"""
    users = ['alice_chen', 'bob_smith', 'charlie_vip', 'diana_emp', 'eve_new']
    tiers = ['basic', 'basic', 'vip', 'basic', 'basic']
    types = ['customer', 'customer', 'customer', 'employee', 'customer']
    countries = ['US', 'US', 'GB', 'US', 'NG']
    devices = ['iphone_14', 'pixel_7', 'macbook_pro', 'work_laptop', 'unknown_device']

    results = []
    for i in range(count):
        idx = random.randint(0, len(users) - 1)
        is_attack = random.random() < 0.3

        event = {
            'user_id': users[idx],
            'user_type': types[idx],
            'account_tier': tiers[idx],
            'event_type': random.choice(['login', 'transaction', 'api_call']),
            'timestamp': (datetime.now() + timedelta(seconds=i)).isoformat(),
            'device_id': devices[idx] if not is_attack else 'unknown_device',
            'ip_address': f'192.168.1.{random.randint(1, 254)}',
            'location_country': countries[idx] if not is_attack else random.choice(['NG', 'RU', 'CN']),
            'session_id': f'sim_session_{i}',
            'amount': random.choice([50, 200, 1000, 5000, 50000]) if is_attack else random.randint(10, 500),
            'is_new_payee': is_attack,
            'success': not is_attack or random.random() > 0.5,
        }
        if is_attack and types[idx] == 'employee':
            event['admin_action'] = 'export_customers'
        if is_attack:
            event['payee_country'] = random.choice(['NG', 'RU', 'CN'])

        try:
            result = pipeline.process_raw_log(event)
            safe = _serialize_result(result)
            if result.get('status') == 'processed':
                record = {
                    'timestamp': datetime.now().isoformat(),
                    'incident': safe.get('incident'),
                    'decision': safe.get('decision'),
                    'playbook': safe.get('playbook'),
                    'playbook_summary': {
                        'id': safe.get('playbook', {}).get('playbook_id'),
                        'action': safe.get('decision', {}).get('action_value'),
                        'risk': safe.get('incident', {}).get('final_risk', 0),
                        'requires_approval': safe.get('decision', {}).get('requires_approval', False),
                        'justification': safe.get('decision', {}).get('justification', ''),
                    }
                }
                incidents_history.append(record)
                await manager.broadcast({
                    'type': 'new_incident',
                    'data': {
                        'incident_id': safe.get('incident', {}).get('incident_id'),
                        'user_id': safe.get('incident', {}).get('user_id'),
                        'risk': safe.get('incident', {}).get('final_risk', 0),
                        'action': safe.get('decision', {}).get('action_value'),
                        'timestamp': datetime.now().isoformat()
                    }
                })
            results.append(safe)
        except Exception as e:
            results.append({'status': 'error', 'error': str(e)})

    return {"simulated": len(results), "results": results}


# ============================================================
# WebSocket
# ============================================================
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ============================================================
# Run
# ============================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
