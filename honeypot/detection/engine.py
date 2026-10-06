from .rules import evaluate

def evaluate_event(source_ip, event_store, rules=None):
    """event_store: dict ip -> list of events. Kept for API parity with backend engine."""
    return evaluate(source_ip, event_store.get(source_ip, []), rules)
