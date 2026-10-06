"""Start SSH + HTTP honeypots (lab, localhost only)."""
import threading
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))
import config
from services.ssh_honeypot import run as run_ssh
from services.http_honeypot import run as run_http

if __name__ == "__main__":
    print("HelloHoney honeypot (LAB/SIMULATION mode) - bind:", config.BIND_HOST)
    t1 = threading.Thread(target=run_ssh, daemon=True)
    t2 = threading.Thread(target=run_http, daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()
