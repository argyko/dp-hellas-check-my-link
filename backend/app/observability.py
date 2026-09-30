from __future__ import annotations
import json, logging, os, time, uuid
from contextlib import contextmanager
from datetime import datetime, timezone

LOGGER = logging.getLogger("check_my_link")

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        extra = getattr(record, "event_data", None)
        if isinstance(extra, dict): payload.update(extra)
        return json.dumps(payload, ensure_ascii=False, default=str)

def configure_logging():
    root=logging.getLogger()
    if getattr(root, "_check_my_link_configured", False): return
    handler=logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root.handlers.clear(); root.addHandler(handler)
    root.setLevel(os.getenv("LOG_LEVEL","INFO").upper())
    root._check_my_link_configured=True

def log_event(event: str, **data):
    LOGGER.info(event, extra={"event_data":{"event":event, **data}})

@contextmanager
def timed_event(event: str, **data):
    started=time.perf_counter(); log_event(event+".started", **data)
    try:
        yield
        log_event(event+".completed", duration_ms=round((time.perf_counter()-started)*1000,2), **data)
    except Exception as exc:
        log_event(event+".failed", duration_ms=round((time.perf_counter()-started)*1000,2), error_type=type(exc).__name__, error=str(exc), **data)
        raise

def new_trace_id(): return str(uuid.uuid4())
