# SecuIR — Banking Threat Intelligence Platform

Real-time incident detection and response system for banking security, featuring ML-driven threat analysis, deterministic rule-based response decisions, and a live SOC dashboard.

## Architecture

```
Raw Logs → Normalization → Deduplication → State Management →
Feature Builders → ML Models → Response Engine → Playbook → Dashboard
```

## Project Structure

```
SecuIR/
├── backend/                  # Python detection & response engine
│   ├── src/                  # Source code
│   │   ├── api_server.py     # FastAPI REST + WebSocket server
│   │   ├── pipeline.py       # Main detection pipeline
│   │   ├── ingestion/        # Log normalization, dedup, reordering
│   │   ├── response/         # Rule engine & playbook generator
│   │   ├── state/            # Session, baseline, risk memory
│   │   ├── features/         # Core & extended feature builders
│   │   └── models/           # ML models (LR + Isolation Forest)
│   ├── tests/                # Test suites
│   ├── data/                 # Training data
│   └── requirements.txt
│
├── frontend/                 # React + Vite dashboard
│   ├── src/
│   │   ├── components/       # Dashboard, Charts, Tables, Modals
│   │   ├── services/         # API client
│   │   ├── App.jsx           # Root component
│   │   └── App.css           # Global styles
│   ├── index.html
│   └── package.json
│
└── README.md
```

## Quick Start

### 1. Install Backend Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Install Frontend Dependencies

```bash
cd frontend
npm install
```

### 3. Start Backend API Server

```bash
cd backend
python src/api_server.py
```

Server runs on `http://localhost:8000`

### 4. Start Frontend Dashboard

```bash
cd frontend
npm run dev
```

Dashboard opens at `http://localhost:5173`

## API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | System info |
| `/api/health` | GET | Health check |
| `/api/ingest` | POST | Ingest single log event |
| `/api/ingest-batch` | POST | Ingest multiple events |
| `/api/incidents` | GET | Recent incidents list |
| `/api/incidents/{id}` | GET | Incident details |
| `/api/playbook/{id}` | GET | Response playbook |
| `/api/stats` | GET | System statistics |
| `/api/simulate` | POST | Generate demo traffic |
| `/ws` | WebSocket | Real-time push updates |

## Running Tests

```bash
# Full system tests (offline, no server needed)
cd backend
python tests/test_full_system.py

# Response engine tests
python tests/test_response.py

# API endpoint tests (requires running server)
python tests/test_api.py

# Connection verification (requires both servers)
python tests/test_connection.py
```

## Demo Scenarios

| Scenario | Expected Response |
|---|---|
| Normal transaction ($100) | `LOG_ONLY` |
| Large transaction to risky country ($50K) | `MFA_CHALLENGE` / `BLOCK_TRANSACTION` |
| VIP user suspicious activity | `MANUAL_REVIEW` (never auto-blocked) |
| Employee data export (10K records) | `FREEZE_ACCOUNT` |
| Credential stuffing (6 failed logins) | `MFA_CHALLENGE` |

## Performance

- **Latency**: < 50ms per event
- **Throughput**: > 100 events/second
- **Memory**: < 200MB under load
