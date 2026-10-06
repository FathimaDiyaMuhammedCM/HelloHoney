"""Safe HTTP honeypot (lab only). Returns harmless responses, logs suspicious paths."""
import json
import uuid
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from collectors.event_collector import send_event, normalize
import config

SUSPICIOUS = ["/admin", "/login", "/wp-admin", "/.env", "/config", "/backup", "/phpmyadmin"]

BACKEND_URL = config.BACKEND_URL


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _handle(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        ip = self.client_address[0]
        path = self.path.split("?")[0]
        suspicious = any(path.startswith(s) or s in path for s in SUSPICIOUS)
        event_type = "WEB_PROBE" if suspicious else "CONNECTION"
        send_event(normalize({
            "eventType": event_type,
            "service": "HTTP",
            "protocol": "TCP",
            "sourceIP": ip,
            "sourcePort": self.client_address[1],
            "destinationPort": config.HTTP_PORT,
            "status": "probed" if suspicious else "connected",
            "severity": "MEDIUM" if suspicious else "INFO",
            "sessionId": f"SES-{uuid.uuid4().hex[:8]}",
            "metadata": {"lab": True, "path": path, "method": self.command},
        }), BACKEND_URL)
        body = b'{"service":"HelloHoney lab honeypot","status":"logged"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle


def run(bind=config.BIND_HOST, port=config.HTTP_PORT):
    srv = HTTPServer((bind, port), Handler)
    print(f"[http] HelloHoney HTTP honeypot on {bind}:{port} (LAB ONLY)")
    srv.serve_forever()


if __name__ == "__main__":
    run()
