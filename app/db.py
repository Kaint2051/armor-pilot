import hashlib
import logging
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/app/data/users.db")

BUILTIN_ROLES = frozenset(["admin", "operator", "viewer"])

# kept for backward compat — callers that just want built-in names use this;
# use get_all_valid_roles() when custom roles must be included.
VALID_ROLES = BUILTIN_ROLES

ROLE_DESCRIPTIONS = {
    "admin":    "Full access: create, approve, reject, delete policies; manage users",
    "operator": "Submit policies for review; cannot approve or apply directly",
    "viewer":   "Read-only: view policies, logs, dashboard",
}


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def get_db():
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with get_db() as conn:
        # Users table — no CHECK on role so custom roles can be stored.
        # Migration: recreate if old schema still has the CHECK constraint.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'viewer',
                created_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                last_login    TEXT
            )
        """)
        # Drop old CHECK constraint if it exists (SQLite requires table rebuild).
        # Must use plain INSERT (not OR IGNORE) so IntegrityError is raised when
        # the old CHECK(role IN ('admin','viewer')) is still present.
        try:
            conn.execute("INSERT INTO users(username,password_hash,role) VALUES('__probe__','x','custom_test_role')")
            conn.execute("DELETE FROM users WHERE username='__probe__'")
        except sqlite3.IntegrityError:
            conn.execute("DROP TABLE IF EXISTS users_old")
            conn.execute("ALTER TABLE users RENAME TO users_old")
            conn.execute("""
                CREATE TABLE users (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    username      TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role          TEXT NOT NULL DEFAULT 'viewer',
                    created_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                    last_login    TEXT
                )
            """)
            conn.execute("INSERT INTO users SELECT * FROM users_old")
            conn.execute("DROP TABLE users_old")

        # Custom roles
        conn.execute("""
            CREATE TABLE IF NOT EXISTS custom_roles (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT UNIQUE NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                permissions TEXT NOT NULL DEFAULT '[]',
                created_at  TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                created_by  TEXT NOT NULL DEFAULT 'system'
            )
        """)

        # Audit events (persistent)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                user       TEXT NOT NULL,
                action     TEXT NOT NULL,
                policy     TEXT NOT NULL DEFAULT '',
                namespace  TEXT NOT NULL DEFAULT '',
                status     TEXT NOT NULL DEFAULT '',
                details    TEXT NOT NULL DEFAULT ''
            )
        """)

        # Policy review queue
        conn.execute("""
            CREATE TABLE IF NOT EXISTS policy_queue (
                id           TEXT PRIMARY KEY,
                name         TEXT NOT NULL,
                namespace    TEXT NOT NULL,
                scope        TEXT NOT NULL,
                manifest     TEXT NOT NULL,
                submitted_by TEXT NOT NULL,
                submitted_at TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                status       TEXT NOT NULL DEFAULT 'pending'
                                 CHECK(status IN ('pending','approving','approved','rejected','cancelled')),
                reviewed_by  TEXT,
                reviewed_at  TEXT,
                review_note  TEXT
            )
        """)

    # Seed default admin
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            admin_user = os.environ.get("ADMIN_USER", "").strip()
            admin_pass = os.environ.get("ADMIN_PASS", "")
            if not admin_user:
                raise RuntimeError("ADMIN_USER must be configured before first startup")
            if len(admin_pass) < 12:
                raise RuntimeError("ADMIN_PASS must be configured with at least 12 characters before first startup")
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (admin_user, hash_password(admin_pass), "admin"),
            )
            logger.info("Seeded default admin user '%s' from environment", admin_user)


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 260_000


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    raw = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), _PBKDF2_ITERATIONS)
    return f"pbkdf2:sha256:{_PBKDF2_ITERATIONS}:{salt}:{raw.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        parts = stored_hash.split(":", 2)
        scheme = parts[0]
        if scheme == "pbkdf2":
            # pbkdf2:sha256:<iterations>:<salt>:<hex>
            _, digest, iters_str, salt, h = stored_hash.split(":", 4)
            iters = int(iters_str)
            raw = hashlib.pbkdf2_hmac(digest, password.encode(), salt.encode(), iters)
            return secrets.compare_digest(raw.hex(), h)
        elif scheme == "sha256":
            # legacy: sha256:<salt>:<hex> — accepted for login, rehashed on next write
            _, salt, h = parts
            candidate = hashlib.sha256((salt + password).encode()).hexdigest()
            return secrets.compare_digest(candidate, h)
        return False
    except Exception:
        return False


# ---------------------------------------------------------------------------
# User CRUD
# ---------------------------------------------------------------------------

def get_user(username: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)
        ).fetchone()
    return dict(row) if row else None


def list_users() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, created_at, last_login FROM users ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def get_all_valid_roles() -> frozenset:
    """Built-in roles + names of all custom roles."""
    custom = {r["name"] for r in list_custom_roles()}
    return BUILTIN_ROLES | frozenset(custom)


def create_user(username: str, password: str, role: str = "viewer") -> None:
    if role not in get_all_valid_roles():
        raise ValueError(f"Invalid role '{role}'")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, hash_password(password), role),
        )


def update_user_password(username: str, new_password: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET password_hash=? WHERE username=?",
            (hash_password(new_password), username),
        )


def update_user_role(username: str, role: str) -> None:
    if role not in get_all_valid_roles():
        raise ValueError(f"Invalid role '{role}'")
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET role=? WHERE username=?", (role, username)
        )


def delete_user(username: str) -> None:
    with get_db() as conn:
        conn.execute("DELETE FROM users WHERE username=?", (username,))


def update_last_login(username: str) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET last_login=strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE username=?",
            (username,),
        )


def get_user_role(username: str) -> str:
    user = get_user(username)
    return user["role"] if user else "viewer"


# ---------------------------------------------------------------------------
# Policy queue CRUD
# ---------------------------------------------------------------------------

def queue_policy(name: str, namespace: str, scope: str,
                 manifest_json: str, submitted_by: str) -> str:
    item_id = str(uuid.uuid4())
    with get_db() as conn:
        conn.execute(
            """INSERT INTO policy_queue
               (id, name, namespace, scope, manifest, submitted_by)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (item_id, name, namespace, scope, manifest_json, submitted_by),
        )
    return item_id


def list_queue(status: str | None = None,
               submitted_by: str | None = None) -> list[dict]:
    with get_db() as conn:
        query = "SELECT * FROM policy_queue WHERE 1=1"
        params: list = []
        if status:
            query += " AND status=?"
            params.append(status)
        if submitted_by:
            query += " AND submitted_by=?"
            params.append(submitted_by)
        query += " ORDER BY submitted_at DESC"
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_queue_item(item_id: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM policy_queue WHERE id=?", (item_id,)
        ).fetchone()
    return dict(row) if row else None


def update_queue_status(item_id: str, status: str,
                        reviewed_by: str | None = None,
                        review_note: str | None = None) -> None:
    with get_db() as conn:
        conn.execute(
            """UPDATE policy_queue
               SET status=?,
                   reviewed_by=?,
                   reviewed_at=strftime('%Y-%m-%dT%H:%M:%SZ','now'),
                   review_note=?
               WHERE id=?""",
            (status, reviewed_by, review_note, item_id),
        )


def claim_queue_item_for_approval(item_id: str, reviewer: str) -> bool:
    """Atomically transition a pending item to 'approving' to prevent double-approve.

    Returns True if the claim succeeded (exactly one row updated), False if the
    item was already claimed or does not exist.
    """
    with get_db() as conn:
        cur = conn.execute(
            """UPDATE policy_queue
               SET status='approving',
                   reviewed_by=?,
                   reviewed_at=strftime('%Y-%m-%dT%H:%M:%SZ','now')
               WHERE id=? AND status='pending'""",
            (reviewer, item_id),
        )
        return cur.rowcount == 1


# ---------------------------------------------------------------------------
# Custom roles CRUD
# ---------------------------------------------------------------------------

def list_custom_roles() -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM custom_roles ORDER BY name"
        ).fetchall()
    return [dict(r) for r in rows]


def get_custom_role(name: str) -> dict | None:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM custom_roles WHERE name=?", (name,)
        ).fetchone()
    return dict(row) if row else None


def create_custom_role(name: str, description: str,
                       permissions: list, created_by: str) -> None:
    import json
    if name in BUILTIN_ROLES:
        raise ValueError(f"Cannot shadow built-in role '{name}'")
    with get_db() as conn:
        conn.execute(
            "INSERT INTO custom_roles (name, description, permissions, created_by) VALUES (?, ?, ?, ?)",
            (name, description, json.dumps(sorted(permissions)), created_by),
        )


def update_custom_role(name: str, description: str, permissions: list) -> None:
    import json
    if name in BUILTIN_ROLES:
        raise ValueError(f"Cannot modify built-in role '{name}'")
    with get_db() as conn:
        conn.execute(
            "UPDATE custom_roles SET description=?, permissions=? WHERE name=?",
            (description, json.dumps(sorted(permissions)), name),
        )


# ---------------------------------------------------------------------------
# Audit events persistence
# ---------------------------------------------------------------------------

def insert_audit_event(user: str, action: str, policy: str,
                       namespace: str, status: str, details: str) -> None:
    with get_db() as conn:
        conn.execute(
            """INSERT INTO audit_events (user, action, policy, namespace, status, details)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (user, action, policy, namespace, status, details),
        )


def get_audit_events(limit: int = 500) -> list[dict]:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def delete_custom_role(name: str) -> None:
    if name in BUILTIN_ROLES:
        raise ValueError(f"Cannot delete built-in role '{name}'")
    with get_db() as conn:
        # Demote any users who had this role to viewer
        conn.execute("UPDATE users SET role='viewer' WHERE role=?", (name,))
        conn.execute("DELETE FROM custom_roles WHERE name=?", (name,))
