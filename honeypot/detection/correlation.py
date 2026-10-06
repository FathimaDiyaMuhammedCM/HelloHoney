"""Group related events into a campaign (correlation by IP + time window + service)."""


def correlate(events):
    """events: list of dicts with sourceIP, eventType, timestamp, service. Returns campaign summary."""
    if not events:
        return None
    ip = events[0].get("sourceIP")
    types = [e.get("eventType") for e in events]
    services = sorted(set(e.get("service") for e in events))
    score = min(100, len([t for t in types if t == "FAILED_LOGIN"]) * 5 + len([t for t in types if t in ("PORT_PROBE", "WEB_PROBE")]) * 10 + (15 if len(set(types)) > 1 else 0))
    return {
        "sourceIP": ip,
        "count": len(events),
        "sequence": types,
        "services": services,
        "riskScore": score,
        "summary": f"Possible intrusion attempt from {ip}: " + " -> ".join(types[:8]),
    }
