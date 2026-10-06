"""Lab simulator: generates synthetic events through the backend simulation API or direct ingest."""
import json
import urllib.request
import uuid

BACKEND = "http://localhost:5000"

def post(path, payload):
    req = urllib.request.Request(BACKEND + path, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            print(r.status, r.read()[:200])
    except Exception as e:
        print("simulate failed:", e)

if __name__ == "__main__":
    import sys
    kind = sys.argv[1] if len(sys.argv) > 1 else "brute-force"
    print(f"[simulator] use the dashboard LAB SIMULATION buttons or POST /api/simulation/{kind} (SIMULATED events)")
