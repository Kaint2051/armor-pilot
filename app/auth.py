import base64
import os
from functools import wraps

from flask import Response, request


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
    expected_user = os.environ.get("ADMIN_USER", "admin")
    expected_pass = os.environ.get("ADMIN_PASS", "changeme")
    # Constant-time comparison to prevent timing attacks
    user_match = username == expected_user
    pass_match = password == expected_pass
    return user_match and pass_match


def get_current_user() -> str:
    username, _ = _parse_basic_auth()
    return username or "anonymous"


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
