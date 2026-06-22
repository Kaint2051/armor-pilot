import collections
import datetime
import logging
import sys

_MAX_EVENTS = 500


class AuditLogger:
    def __init__(self):
        # In-memory cache for fast recent-events access (last _MAX_EVENTS entries)
        self._events: collections.deque = collections.deque(maxlen=_MAX_EVENTS)
        self.logger = logging.getLogger("varmor.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            handler.setLevel(logging.INFO)
            handler.setFormatter(logging.Formatter(
                "[%(asctime)s] [AUDIT] %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%SZ",
            ))
            self.logger.addHandler(handler)

    def log(self, user: str, action: str, policy_name: str, namespace: str,
            status: str, details: str = "") -> None:
        parts = [
            f"user={user}", f"action={action}", f"policy={policy_name}",
            f"namespace={namespace}", f"status={status}",
        ]
        if details:
            parts.append(f'details="{details}"')
        self.logger.info(" ".join(parts))
        event = {
            "ts": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "user": user,
            "action": action,
            "policy": policy_name,
            "namespace": namespace,
            "status": status,
            "details": details,
        }
        self._events.append(event)
        # Persist to SQLite — non-fatal if DB is unavailable
        try:
            from .db import insert_audit_event
            insert_audit_event(user, action, policy_name, namespace, status, details)
        except Exception as exc:
            self.logger.warning("Could not persist audit event to DB: %s", exc)

    def get_events(self, limit: int = 500):
        # Prefer DB (survives restarts); fall back to in-memory cache
        try:
            from .db import get_audit_events
            return get_audit_events(limit=limit)
        except Exception:
            return list(reversed(self._events))[:limit]


audit_logger = AuditLogger()
