from collections import deque
from threading import Lock

# Small in-memory history for a local classroom demo; cleared on restart.
_HISTORY = deque(maxlen=30)
_LOCK = Lock()

def add_scan(result):
    record = {
        "timestamp": result.get("timestamp"),
        "hostname": result.get("hostname"),
        "risk_score": result.get("risk_score"),
        "risk_band": result.get("risk_band"),
        "dns_status": result.get("dns_status"),
        "total_ms": result.get("timings_ms", {}).get("total")
    }
    with _LOCK:
        _HISTORY.appendleft(record)

def get_recent_scans():
    with _LOCK:
        return list(_HISTORY)
