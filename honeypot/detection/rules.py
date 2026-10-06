"""Rule-based detection engine (mirrors backend Node engine for standalone/lab analysis)."""
import datetime

DEFAULT_RULES = [
    {"name": "SSH Brute Force", "eventType": "FAILED_LOGIN", "threshold": 5, "timeWindow": 60, "severity": "HIGH", "attackType": "SSH Brute Force", "enabled": True},
    {"name": "Port Scan", "eventType": "PORT_PROBE", "threshold": 3, "timeWindow": 60, "severity": "MEDIUM", "attackType": "Port Scan", "enabled": True},
    {"name": "Web Reconnaissance", "eventType": "WEB_PROBE", "threshold": 3, "timeWindow": 120, "severity": "MEDIUM", "attackType": "Web Reconnaissance", "enabled": True},
    {"name": "Rapid Connections", "eventType": "CONNECTION", "threshold": 10, "timeWindow": 30, "severity": "MEDIUM", "attackType": "Repeated Connection Activity", "enabled": True},
    {"name": "Multi-Stage Attack", "eventType": "FAILED_LOGIN", "threshold": 3, "timeWindow": 600, "severity": "HIGH", "attackType": "Multi-Stage Attack", "enabled": True},
]


def within(events, seconds):
    now = datetime.datetime.utcnow()
    return [e for e in events if (now - e["ts"]).total_seconds() <= seconds]


def evaluate(source_ip, events, rules=None):
    """events: list of dicts {eventType, ts, destinationPort}. Returns list of alert dicts."""
    rules = rules or DEFAULT_RULES
    alerts = []
    for r in rules:
        if not r.get("enabled"):
            continue
        name = r["name"]
        if name == "SSH Brute Force":
            fails = [e for e in within(events, r["timeWindow"]) if e["eventType"] in ("FAILED_LOGIN", "TEST_LOGIN")]
            if len(fails) >= r["threshold"]:
                alerts.append({"attackType": r["attackType"], "severity": r["severity"], "description": f"{len(fails)} failed logins from {source_ip}", "rule": name})
        elif name == "Port Scan":
            probes = within(events, r["timeWindow"])
            probes = [e for e in probes if e["eventType"] in ("PORT_PROBE", "CONNECTION")]
            ports = set(e.get("destinationPort") for e in probes)
            if len(ports) >= r["threshold"]:
                alerts.append({"attackType": r["attackType"], "severity": r["severity"], "description": f"Port scan: {len(ports)} ports", "rule": name})
        elif name == "Web Reconnaissance":
            probes = [e for e in within(events, r["timeWindow"]) if e["eventType"] in ("WEB_PROBE", "SUSPICIOUS_REQUEST")]
            if len(probes) >= r["threshold"]:
                alerts.append({"attackType": r["attackType"], "severity": r["severity"], "description": f"{len(probes)} web probes", "rule": name})
        elif name == "Rapid Connections":
            conns = [e for e in within(events, r["timeWindow"]) if e["eventType"] == "CONNECTION"]
            if len(conns) >= r["threshold"]:
                alerts.append({"attackType": r["attackType"], "severity": r["severity"], "description": f"{len(conns)} rapid connections", "rule": name})
        elif name == "Multi-Stage Attack":
            windowed = within(events, r["timeWindow"])
            types = set(e["eventType"] for e in windowed)
            fails = [e for e in windowed if e["eventType"] in ("FAILED_LOGIN", "TEST_LOGIN")]
            if ("PORT_PROBE" in types or "CONNECTION" in types) and len(fails) >= r["threshold"]:
                alerts.append({"attackType": r["attackType"], "severity": r["severity"], "description": "probe + SSH + failed logins", "rule": name})
    return alerts
