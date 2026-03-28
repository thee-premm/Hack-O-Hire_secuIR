# SecuIR Backend

Python-based incident detection and response engine.

## Components

- **`api_server.py`** — FastAPI REST + WebSocket server
- **`pipeline.py`** — Main detection pipeline (normalize → dedup → features → ML → rules → playbook)
- **`ingestion/`** — Log normalization, deduplication, reordering
- **`response/`** — Priority-based rule engine (12 rules) and playbook generator
- **`state/`** — Session, baseline, and risk memory managers
- **`features/`** — Core (11 features) and extended feature builders
- **`models/`** — Logistic Regression + Isolation Forest models

## Running

```bash
pip install -r requirements.txt
python src/api_server.py
```

## Tests

```bash
python tests/test_full_system.py    # 17 test cases
python tests/test_response.py       # Response engine unit tests
python tests/test_api.py            # API endpoint tests (server required)
```
