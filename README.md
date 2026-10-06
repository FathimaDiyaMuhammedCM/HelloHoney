# 🛡️ HELLOHONEY (HONEYWATCH SOC)

Defensive honeypot-based attack detection, monitoring & incident response platform for an **authorized local lab only**.

## Architecture

```
Test machine -> SSH/HTTP honeypot (Python, localhost:2222/8080)
  -> Event collector (POST /api/ingest/events, normalized)
  -> MongoDB (or in-memory Mongo for lab demo)
  -> Detection engine (Node service + Python mirror)
  -> Alerts -> Incident correlation -> Risk score (HoneyWatch Risk Score, project-defined)
  -> SOC dashboard (React) -> Reports (PDF/CSV)
```

## Prerequisites
- Node 20+, Python 3.10+, MongoDB (optional; in-memory fallback included for lab demo)

## Quick start
```bash
# backend
cd backend && npm install && node server.js
# seed demo data (optional)
node ../database/seed.js
# frontend
cd ../frontend && npm install && npm run dev
# honeypot (lab, localhost only)
cd ../honeypot && python main.py
```

Default logins: `admin@hellohoney.local / Admin123!`, `analyst@hellohoney.local / Analyst123!`, `viewer@hellohoney.local / Viewer123!`.

## Acceptance demo
1. Start backend (`node backend/server.js`), frontend (`npm run dev` in frontend).
2. Login, open Dashboard.
3. Click **Failed SSH Login** simulation → event appears in Recent Events.
4. Click **SSH Brute Force** (10 failed logins) → HIGH **SSH Brute Force** alert appears + incident auto-created.
5. Open alert → linked events; open incident → timeline; generate PDF report.

## Safety (lab only)
- Honeypot binds `127.0.0.1` by default; never expose to the Internet.
- No shell, no command execution, no real credentials; passwords stored only as `len=N (redacted)`.
- All synthetic events labeled `SIMULATED`; seed data labeled `DEMO DATA`.

## API (see docs/16-api.md)
Auth, events, alerts, incidents, attackers, analytics, rules, IOCs, reports, simulation, system, audit.

## Tests
- `node tests/run_tests.js` (risk scoring)
- `python -m pytest honeypot/detection/test_rules.py -v` (brute-force, port-scan, web-recon, risk cap)
