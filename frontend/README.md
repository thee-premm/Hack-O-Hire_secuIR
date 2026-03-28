# SecuIR Frontend

React + Vite dashboard for real-time banking threat intelligence visualization.

## Features

- **Live Dashboard** — Real-time incident metrics and risk trends
- **Risk Chart** — Gradient area chart showing risk score progression
- **Incident Table** — Filterable table with risk bars and action chips
- **Alert Cards** — Color-coded recent alert feed
- **Playbook Modal** — Full incident playbook with investigation steps and approval workflow
- **Simulate Traffic** — One-click demo traffic generation

## Tech Stack

- React 18 + Vite
- Material UI 5 (dark theme)
- Recharts (charts)
- Axios (API client)
- WebSocket (real-time push)

## Running

```bash
npm install
npm run dev
```

Dashboard opens at `http://localhost:5173`

Requires the backend API server running on `http://localhost:8000`.
