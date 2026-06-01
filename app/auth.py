import base64
import logging
from functools import wraps

from flask import Response, request

logger = logging.getLogger(__name__)


def _parse_basic_auth():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Basic "):
        return None, None
    try:
        decoded = base64.b64decode(auth[6:]).decode("utf-8")
        username, password = decoded.split(":", 1)
        return username, password
    except Exception:
        return None, None


def _credentials_valid(username: str, password: str) -> bool:
    from .db import get_user, verify_password, update_last_login
    user = get_user(username)
    if not user:
        return False
    if not verify_password(password, user["password_hash"]):
        return False
    try:
        update_last_login(username)
    except Exception as exc:
        logger.warning("Could not update last_login for %s: %s", username, exc)
    return True


def get_current_user() -> str:
    username, _ = _parse_basic_auth()
    return username or "anonymous"


def get_current_role() -> str:
    username, _ = _parse_basic_auth()
    if not username:
        return "viewer"
    from .db import get_user_role
    return get_user_role(username)


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        username, password = _parse_basic_auth()
        if not username or not _credentials_valid(username, password):
            return Response(
                '{"error": "Unauthorized: invalid or missing credentials"}',
                status=401,
                headers={
                    "WWW-Authenticate": 'Basic realm="vArmor Console"',
                    "Content-Type": "application/json",
                },
            )
        return f(*args, **kwargs)
    return decorated


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        username, password = _parse_basic_auth()
        if not username or not _credentials_valid(username, password):
            return Response(
                '{"error": "Unauthorized"}', status=401,
                headers={"Content-Type": "application/json"},
            )
        from .db import get_user_role
        if get_user_role(username) != "admin":
            return Response(
                '{"error": "Forbidden: admin role required"}', status=403,
                headers={"Content-Type": "application/json"},
            )
        return f(*args, **kwargs)
    return decorated
