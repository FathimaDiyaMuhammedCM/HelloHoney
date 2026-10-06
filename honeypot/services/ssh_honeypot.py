"""Safe SSH-style honeypot (lab only, localhost by default).
Never executes client input, never provides a shell, never stores real passwords.
"""
import socket
import threading
import uuid
import datetime
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from collectors.event_collector import send_event, normalize
import config


def handle_client(conn, addr, backend_url):
    source_ip, source_port = addr[0], addr[1]
    session_id = f"SES-{uuid.uuid4().hex[:8]}"
    try:
        conn.settimeout(20)
        conn.sendall(b"SSH-2.0-HelloHoney_Lab\r\n")
        conn.sendall(b"HelloHoney lab honeypot. Test access only. All activity is logged.\r\nlogin: ")
        username = conn.recv(256).decode("utf-8", errors="ignore").strip()[:64] or "unknown"
        conn.sendall(b"password (test only): ")
        pw = conn.recv(256).decode("utf-8", errors="ignore").strip()
        # NEVER store plaintext: only record length representation via collector
        conn.sendall(b"\r\nAccess denied (lab trap). Connection logged.\r\n")
        event = normalize({
            "eventType": "FAILED_LOGIN",
            "service": "SSH",
            "sourceIP": source_ip,
            "sourcePort": source_port,
            "destinationPort": config.SSH_PORT,
            "username": username,
            "passwordAttempt": pw,
            "status": "failed",
            "severity": "MEDIUM",
            "sessionId": session_id,
            "metadata": {"lab": True, "banner": "SSH-2.0-HelloHoney_Lab"},
        })
        send_event(event, backend_url)
        # also log a CONNECTION event
        send_event(normalize({
            "eventType": "CONNECTION", "service": "SSH",
            "sourceIP": source_ip, "sourcePort": source_port,
            "destinationPort": config.SSH_PORT, "status": "connected",
            "severity": "INFO", "sessionId": session_id, "metadata": {"lab": True},
        }), backend_url)
    except Exception as e:
        print(f"[ssh] session error: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def run(bind=config.BIND_HOST, port=config.SSH_PORT, backend_url=config.BACKEND_URL):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((bind, port))
    except OSError as e:
        print(f"[ssh] cannot bind {bind}:{port}: {e}")
        return
    srv.listen(20)
    print(f"[ssh] HelloHoney SSH honeypot listening on {bind}:{port} (LAB ONLY)")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr, backend_url), daemon=True).start()


if __name__ == "__main__":
    run()
