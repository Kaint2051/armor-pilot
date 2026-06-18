import base64
import logging
from functools import wraps

from flask import Response, request

from .product import PRODUCT_NAME

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Permission catalogue
# ---------------------------------------------------------------------------

ALL_PERMISSIONS: frozenset = frozenset({
    "dashboard:view",
    "policies:view", "policies:create", "policies:validate",
    "policies:submit", "policies:edit", "policies:delete",
    "policies:apply_direct", "policies:import", "policies:export",
    "review:view", "review:approve", "review:reject", "review:cancel",
    "logs:view", "logs:audit", "logs:violations", "logs:apparmor",
    "models:view", "models:advisor", "models:apply",
    "secrets:view", "secrets:create", "secrets:update", "secrets:delete",
    "users:view", "users:create", "users:update_role",
    "users:reset_password", "users:delete",
    "license:view", "license:manage",
    "system:view", "system:health",
})

_VIEWER_PERMS: frozenset = frozenset({
    "dashboard:view",
    "policies:view",
    "logs:view", "logs:audit", "logs:violations", "logs:apparmor",
    "models:view",
    "secrets:view",
    "license:view",
    "system:view", "system:health",
})

_OPERATOR_PERMS: frozenset = _VIEWER_PERMS | frozenset({
    "policies:create", "policies:validate", "policies:submit",
    "policies:export", "policies:import",
    "review:view",
})

ROLE_PERMISSIONS: dict = {
    "viewer":   _VIEWER_PERMS,
    "operator": _OPERATOR_PERMS,
    "admin":    ALL_PERMISSIONS,
}


def get_permissions_for_role(role: str) -> frozenset:
    if role in ROLE_PERMISSIONS:
        return ROLE_PERMISSIONS[role]
    # custom role — look up permissions from DB
    try:
        import json
        from .db import get_custom_role
        cr = get_custom_role(role)
        if cr:
            return frozenset(json.loads(cr["permissions"]))
    except Exception:
        pass
    return _VIEWER_PERMS


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

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


def current_user_has_permission(perm: str) -> bool:
    """Check if the currently authenticated user has a given permission."""
    username, _ = _parse_basic_auth()
    if not username:
        return False
    from .db import get_user_role
    return perm in get_permissions_for_role(get_user_role(username))


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        username, password = _parse_basic_auth()
        if not username or not _credentials_valid(username, password):
            return Response(
                '{"error": "Unauthorized: invalid or missing credentials"}',
                status=401,
                headers={
                    "WWW-Authenticate": f'Basic realm="{PRODUCT_NAME}"',
                    "Content-Type": "application/json",
                },
            )
        return f(*args, **kwargs)
    return decorated


def require_permission(perm: str):
    """Decorator factory — require a specific permission (checks auth too)."""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            username, password = _parse_basic_auth()
            if not username or not _credentials_valid(username, password):
                return Response(
                    '{"error": "Unauthorized"}', status=401,
                    headers={
                        "WWW-Authenticate": f'Basic realm="{PRODUCT_NAME}"',
                        "Content-Type": "application/json",
                    },
                )
            from .db import get_user_role
            role = get_user_role(username)
            if perm not in get_permissions_for_role(role):
                return Response(
                    f'{{"error": "Forbidden: permission \\"{perm}\\" required"}}',
                    status=403,
                    headers={"Content-Type": "application/json"},
                )
            return f(*args, **kwargs)
        return decorated
    return decorator


# Legacy decorators — kept for endpoints not yet migrated; internally they
# map to the equivalent permission check so behaviour is identical.

def require_admin(f):
    """Legacy: equivalent to require_permission('policies:apply_direct')
    for policy endpoints, but any admin-only permission works as the gate.
    Admin is the only role that has users:view, so that's the safest gate."""
    return require_permission("users:view")(f)


def require_operator(f):
    """Legacy: allow admin and operator — equivalent to policies:submit."""
    return require_permission("policies:submit")(f)
