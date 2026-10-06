import json
import urllib.request
import datetime

def send_event(event, backend_url="http://localhost:5000"):
    """Send normalized event to backend ingest API."""
    url = backend_url.rstrip("/") + "/api/ingest/events"
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status
    except Exception as e:
        print(f"[collector] failed to send event: {e}")
        return None


def normalize(base):
    base.setdefault("timestamp", datetime.datetime.utcnow().isoformat() + "Z")
    base.setdefault("protocol", "TCP")
    base.setdefault("honeypotId", "honeypot-01")
    return base
