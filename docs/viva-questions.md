# Viva Questions (50, beginner-friendly)

1. What is a honeypot? — A decoy system that attracts attackers so we can observe techniques safely.
2. Low vs high interaction honeypot? — Low emulates banners only (ours); high gives real OS (risky).
3. What is a SIEM? — Collects/normalizes logs, detects, alerts; we are a mini-SIM + SOC UI.
4. What is a SOC? — Team/process + dashboard triaging alerts → incidents.
5. IDS vs IPS? — IDS detects/alerts; IPS blocks. We detect only.
6. What is an event vs alert vs incident? — Raw observation → fired rule → correlated investigation case.
7. Why normalize events? — Common schema (IP, service, type, severity) so rules work across SSH/HTTP.
8. Why MongoDB here? — Flexible JSON-like docs for varied event metadata; easy time/IP indexes.
9. What indexes and why? — (timestamp, sourceIP, eventType, service) for dashboard/analytics speed.
10. How does SSH brute-force rule work? — >5 FAILED_LOGIN same IP in 60s → HIGH alert.
11. How is port scan detected? — 3+ distinct destination ports in 60s.
12. Web recon? — 3+ suspicious paths (e.g. /.env, /wp-admin) in 120s.
13. Multi-stage? — Probe + SSH + ≥3 failed logins in 10 min → HIGH + incident.
14. How do you avoid duplicate alerts? — Dedupe OPEN alert same rule+IP within window.
15. What is correlation? — Group by IP/session/time into one campaign instead of N isolated events.
16. HoneyWatch Risk Score? — Project-defined 0–100: login +5, probe +10, multi-type +15, high alert +20, repeat +10; LOW 0–20 … CRITICAL 76–100. Not an industry standard.
17. What is an IOC? — Indicator (IP/domain/URL/hash/username) analysts track; lab-only list here.
18. False positive handling? — Alert status FALSE_POSITIVE; tune thresholds/disable rules.
19. JWT auth flow? — Login → signed token → Bearer header → middleware verifies → RBAC by role.
20. RBAC roles? — ADMIN full; ANALYST triage+IOCs+reports; VIEWER read-only.
21. Why bcrypt? — Salted one-way hash; never store plaintext.
22. What is audit logging? — Who did what, when, from where (logins, status changes, rules, reports).
23. REST endpoints for events? — GET /api/events, GET /api/events/:id; ingest POST /api/ingest/events.
24. How do reports avoid leaking secrets? — Exclude passwordEcho; only metadata/counts.
25. PDF vs CSV? — PDF narrative (summary, timeline, recommendations); CSV raw rows for analysis.
26. Polling vs WebSocket? — Poll every 4s by default (reliable); Socket.IO emits new_event/new_alert/incident_update ready.
27. React structure? — pages/ (Dashboard, Events, Alerts, …), components/ (badges, tables, charts), services/api (axios+JWT), context/AuthContext, hooks/usePolling.
28. What is Recharts used for? — Events-over-time, attack types, severity pie, top IPs/services.
29. Express middleware used? — helmet, cors, rate-limit, morgan, auth, error handler, 404.
30. Why dotenv? — Secrets (JWT, DB URI) from env, never hardcoded.
31. What does the SSH honeypot do? — Accept TCP, fake banner, read username/test password, log event, deny, close. No shell.
32. What must the honeypot NEVER do? — Execute input, give shell, touch filesystem, exploit/scan others.
33. HTTP honeypot suspicious paths? — /admin, /login, /wp-admin, /.env, /config, /backup, /phpmyadmin.
34. Simulation mode? — Buttons POST synthetic events (SIMULATED) through the same pipeline.
35. Seed data? — 120 events, 22 alerts, 2 incidents, 4 attackers labeled DEMO DATA.
36. Incident lifecycle? — OPEN → INVESTIGATING → RESOLVED with timeline + notes + assignee.
37. Attacker view? — Group by IP: events, alerts, incidents, timeline, risk; no fake geolocation for private IPs.
38. MITRE ATT&CK mapping? — Brute force ≈ T1110, scanning ≈ T1046, web recon ≈ T1595 (conceptual).
39. How to test brute force? — Simulate 10 failed logins → expect HIGH alert + incident.
40. Port unavailable? — Honeypot logs bind error and exits cleanly; DB down → collector retries/logs.
41. Rate limiting? — 600 req/min per IP on API.
42. CORS? — Only FRONTEND_URL origins.
43. In-memory Mongo fallback? — If local Mongo down, mongodb-memory-server starts so lab demo works.
44. How are passwords handled? — Client input discarded; stored as redacted length only.
45. Docker Compose services? — mongodb, backend, frontend (honeypot not exposed).
46. Threat model? — Lab attacker on private net probing honeypot; defender monitors dashboard.
47. What would you demo in viva? — Failed login → event; brute force → HIGH alert; incident timeline; PDF.
48. Limitations? — Threshold rules can false-positive; no ML; single node; lab scale.
49. Future scope? — ML anomaly detection, MITRE tags, ticketing, real-time SIEM feeds.
50. Why is this defensive only? — No exploitation, no scanning of others, isolated lab, education purpose.
