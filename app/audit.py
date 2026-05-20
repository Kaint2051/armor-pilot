import collections
import datetime
import logging
import sys

_MAX_EVENTS = 500


class AuditLogger:
    def __init__(self):
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
        self._events.append({
            "ts": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "user": user,
            "action": action,
            "policy": policy_name,
            "namespace": namespace,
            "status": status,
            "details": details,
        })

    def get_events(self):
        return list(reversed(self._events))


audit_logger = AuditLogger()
