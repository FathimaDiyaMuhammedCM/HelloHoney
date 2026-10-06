import datetime


def test_brute_force():
    from honeypot.detection.rules import evaluate
    now = datetime.datetime.utcnow()
    events = [{"eventType": "FAILED_LOGIN", "ts": now, "destinationPort": 2222} for _ in range(6)]
    alerts = evaluate("192.168.56.20", events)
    assert any(a["attackType"] == "SSH Brute Force" for a in alerts)


def test_port_scan():
    from honeypot.detection.rules import evaluate
    now = datetime.datetime.utcnow()
    events = [{"eventType": "PORT_PROBE", "ts": now, "destinationPort": p} for p in [22, 80, 443, 2222]]
    alerts = evaluate("192.168.56.21", events)
    assert any(a["attackType"] == "Port Scan" for a in alerts)


def test_web_recon():
    from honeypot.detection.rules import evaluate
    now = datetime.datetime.utcnow()
    events = [{"eventType": "WEB_PROBE", "ts": now, "destinationPort": 8080} for _ in range(4)]
    alerts = evaluate("10.0.2.20", events)
    assert any(a["attackType"] == "Web Reconnaissance" for a in alerts)


def test_risk_cap():
    from honeypot.detection.correlation import correlate
    events = [{"sourceIP": "1.1.1.1", "eventType": "FAILED_LOGIN", "service": "SSH"} for _ in range(50)]
    c = correlate(events)
    assert c["riskScore"] <= 100
