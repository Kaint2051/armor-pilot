import hashlib
import logging
import os
import secrets
import sqlite3
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("DB_PATH", "/app/data/users.db")


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
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'viewer'
                                  CHECK(role IN ('admin','viewer')),
                created_at    TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
                last_login    TEXT
            )
        """)
    # Seed default admin from env vars if table is empty
    with get_db() as conn:
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            admin_user = os.environ.get("ADMIN_USER", "admin")
            admin_pass = os.environ.get("ADMIN_PASS", "changeme")
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (admin_user, hash_password(admin_pass), "admin"),
            )
            logger.info("Seeded default admin user '%s' from environment", admin_user)


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"sha256:{salt}:{h}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        _, salt, h = stored_hash.split(":", 2)
        candidate = hashlib.sha256((salt + password).encode()).hexdigest()
        return secrets.compare_digest(candidate, h)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# CRUD
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


def create_user(username: str, password: str, role: str = "viewer") -> None:
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
