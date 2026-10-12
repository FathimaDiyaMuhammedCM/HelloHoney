# HelloHoney System Documentation

## 01 Introduction
HelloHoney (HelloHoney SOC) is a defensive lab platform: a controlled honeypot observes suspicious activity; a detection engine fires alerts; correlation builds incidents; a SOC dashboard supports investigation and reporting.

## 02-06 Problem / Existing / Proposed / Objectives / Scope
Problem: student labs lack an affordable way to practise detection → triage → response.
Existing: production SIEMs are heavy/expensive; raw honeypots lack analytics.
Proposed: lightweight honeypot + Node API + MongoDB + React SOC in one repo.
Objectives: observe safely, detect 5 attack classes, correlate campaigns, score risk, report.
Scope: localhost/private lab only; no exploitation, no public exposure.

## 07-08 Functional / Non-functional requirements
Functional: honeypot, ingest/normalize, detection rules, alerts, incidents, attackers, analytics, rules UI, IOCs, PDF/CSV, simulation, auth/RBAC, audit, health.
Non-functional: lab-safe defaults, polling + Socket.IO-ready realtime, validated inputs, no plaintext secrets.

## 09-10 Architecture / Data flow
Honeypot (Py) → POST /api/ingest/events → normalize → MongoDB → detectionService.evaluateEvent → Alert (+Attacker update, risk) → auto-incident → Socket.IO emit → React polls (4s) / sockets → Reports from live DB.

## 11 Database design
User, Event (indexed timestamp/sourceIP/eventType/service/severity), Alert, Incident, DetectionRule, Attacker (by IP), IOC, AuditLog, SystemSetting, Report.

## 12-14 Detection engine / Rules / Risk scoring
Rules: SSH Brute Force (>5 fails/60s/HIGH), Port Scan (3+ ports/60s), Web Recon (3+ paths/120s), Rapid Connections (10+/30s), Multi-Stage (probe+SSH+fails/10min). Dedupe per rule+IP+window.
Risk: HelloHoney Risk Score (project-defined): failed login +5, probe +10, multi-type +15, high alert +20, repeated +10, cap 100; LOW 0–20, MEDIUM 21–50, HIGH 51–75, CRITICAL 76–100.

## 15 Incident management
OPEN → INVESTIGATING → RESOLVED; sourceIPs, linked alerts/events, assignee, timeline, notes.

## 16 API documentation
AUTH: POST /api/auth/login|register, GET /api/auth/me. EVENTS: GET /api/events|/:id; ingest POST /api/ingest/events. ALERTS: GET, PATCH /:id/status. INCIDENTS: GET/POST/GET/PATCH/POST notes. ATTACKERS, ANALYTICS (summary/timeline/attacks/severity/top-ips/services), RULES CRUD, IOCS CRUD, REPORTS (POST pdf, GET csv), SIMULATION ×5, SYSTEM health/status, AUDIT GET /api/audit-logs.

## 17-23 UI / Testing / Results / Limitations / Future / Conclusion / References
Dark SOC theme, sidebar+status bar, cards/charts/tables/timelines/badges. Tests: pytest (4 rules) + node risk tests + acceptance flow. Results: simulation → event → HIGH alert → incident → PDF verified. Limitations: threshold rules, single node, lab scale. Future: ML, MITRE tags, ticketing. References: Express/Mongoose/React docs, OWASP honeypot guidance, MITRE ATT&CK (concepts).
