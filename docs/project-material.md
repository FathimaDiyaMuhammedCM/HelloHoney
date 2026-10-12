# HelloHoney — B.Tech Project Material (abstract, objectives, methodology, viva pointers)

## Abstract
HelloHoney (HelloHoney SOC) is a defensive lab platform that deploys a controlled SSH/HTTP honeypot, normalizes suspicious activity into security events, applies a modular rule-based detection engine, correlates campaigns into alerts and incidents, scores risk with a project-defined HelloHoney Risk Score, and presents SOC monitoring, investigation, analytics and PDF/CSV reporting with JWT authentication, RBAC and audit logging.

## Problem statement
Small labs and student SOCs lack an affordable, self-contained way to observe attacker techniques (brute force, scanning, web recon) and practise detection → triage → incident response.

## Objectives / Scope
Observe only (no exploitation); detect 5 attack classes; group by attacker IP; manage incidents with timeline/notes; report; simulate attacks safely in LAB mode.

## Methodology
Honeypot → collector/normalization → MongoDB → rules → alerts → correlation/incidents → risk → dashboard → reports. Simulation events traverse the same pipeline.

## Modules
Honeypot services, collector, detection engine, correlation, backend REST API + Socket.IO, React SOC UI, reports, auth/RBAC/audit, simulation, seed/tests.

## Testing
Unit tests for rules (pytest) and risk scoring (node); acceptance flow: 1 failed login → event; 10 failed logins → HIGH SSH Brute Force alert + incident.

## Limitations / Future
Single-node lab; signature/threshold rules only (no ML); no public exposure; future: Zeek/Suricata feed, MITRE mapping, ML anomaly detection, ticketing/SOAR webhooks.

See docs/viva-questions.md for 50+ viva Q&A.
