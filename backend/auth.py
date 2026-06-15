"""
Cortex Authentication Module
==============================
JWT-based authentication with multi-user SQLite storage.

Features:
  - bcrypt password hashing via passlib
  - HS256 JWT tokens via python-jose
  - Auto-generates admin user with random password on first run
  - Role-based: admin (full access) | analyst (read-only scan access)
  - Token expiry configurable via CORTEX_JWT_EXPIRE_HOURS env var
  - API key support: long-lived tokens for CI/CD use

Dependencies (add to requirements.txt):
  python-jose[cryptography]==3.3.0
  passlib[bcrypt]==1.7.4
"""

from __future__ import annotations

import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

# ── Optional imports — fail gracefully if not installed ──────────────────────
try:
    from jose import JWTError, jwt as _jwt
    JOSE_AVAILABLE = True
except ImportError:
    JOSE_AVAILABLE = False

try:
    from passlib.context import CryptContext
    _pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")
    PASSLIB_AVAILABLE = True
except ImportError:
    PASSLIB_AVAILABLE = False
    _pwd_ctx = None

AUTH_AVAILABLE = JOSE_AVAILABLE and PASSLIB_AVAILABLE

# ── Config ────────────────────────────────────────────────────────────────────
_SECRET_KEY_ENV = "CORTEX_JWT_SECRET"
_EXPIRE_HOURS   = int(os.environ.get("CORTEX_JWT_EXPIRE_HOURS", "24"))
_ALGORITHM      = "HS256"
_DATA_DIR       = Path(os.environ.get("CORTEX_DATA_DIR", "/data"))
_DB_PATH        = _DATA_DIR / "cortex.db"


def _get_secret() -> str:
    """Return JWT secret from env or generate+persist a stable one."""
    env = os.environ.get(_SECRET_KEY_ENV, "")
    if env:
        return env
    # Persist in a file so it survives restarts
    key_file = _DATA_DIR / ".jwt_secret"
    try:
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        if key_file.exists():
            return key_file.read_text().strip()
        key = secrets.token_hex(32)
        key_file.write_text(key)
        key_file.chmod(0o600)
        return key
    except Exception:
        return secrets.token_hex(32)  # ephemeral fallback


# ── Database helpers ──────────────────────────────────────────────────────────
def _conn() -> sqlite3.Connection:
    _DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_auth_db():
    """Create users and api_keys tables. Safe to call multiple times."""
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                email       TEXT,
                password_hash TEXT NOT NULL,
                role        TEXT NOT NULL DEFAULT 'analyst',
                active      INTEGER NOT NULL DEFAULT 1,
                created_at  TEXT DEFAULT (datetime('now')),
                last_login  TEXT
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                key_hash    TEXT UNIQUE NOT NULL,
                key_prefix  TEXT NOT NULL,
                username    TEXT NOT NULL,
                label       TEXT,
                role        TEXT NOT NULL DEFAULT 'analyst',
                created_at  TEXT DEFAULT (datetime('now')),
                last_used   TEXT,
                expires_at  TEXT,
                active      INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
            CREATE INDEX IF NOT EXISTS idx_api_keys_hash  ON api_keys(key_hash);
        """)
    # Ensure admin exists
    _ensure_admin()


def _ensure_admin():
    """Create the admin user on first run, printing credentials to stdout."""
    try:
        with _conn() as conn:
            row = conn.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1").fetchone()
            if row:
                return
            # First run — generate random password
            password = secrets.token_urlsafe(16)
            hashed   = hash_password(password)
            conn.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("admin", hashed, "admin"),
            )
        # Print credentials to stdout (visible in Docker logs)
        sep = "=" * 60
        print(f"\n{sep}")
        print("  Cortex — Admin account created (first run)")
        print(f"  Username : admin")
        print(f"  Password : {password}")
        print(f"  Change with: POST /api/auth/change-password")
        print(f"{sep}\n")
    except Exception as e:
        print(f"[auth] _ensure_admin error: {e}")


# ── Password helpers ──────────────────────────────────────────────────────────
def hash_password(plain: str) -> str:
    if not PASSLIB_AVAILABLE:
        raise RuntimeError("passlib not installed — run: pip install passlib[bcrypt]")
    # bcrypt hard limit is 72 bytes; truncate to avoid passlib error
    if len(plain.encode()) > 72:
        plain = plain.encode()[:72].decode(errors="ignore")
    return _pwd_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    if not PASSLIB_AVAILABLE:
        return False
    try:
        return _pwd_ctx.verify(plain, hashed)
    except Exception:
        return False


# ── User CRUD ─────────────────────────────────────────────────────────────────
def get_user(username: str) -> dict | None:
    try:
        with _conn() as conn:
            row = conn.execute(
                "SELECT id, username, email, role, active, created_at, last_login FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            return dict(row) if row else None
    except Exception:
        return None


def authenticate_user(username: str, password: str) -> dict | None:
    """Verify credentials. Returns user dict or None."""
    try:
        with _conn() as conn:
            row = conn.execute(
                "SELECT id, username, email, role, active, password_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        if not row:
            return None
        user = dict(row)
        if not user.get("active"):
            return None
        if not verify_password(password, user.pop("password_hash")):
            return None
        # Update last_login
        with _conn() as conn:
            conn.execute(
                "UPDATE users SET last_login = datetime('now') WHERE username = ?",
                (username,)
            )
        return user
    except Exception:
        return None


def create_user(username: str, password: str, role: str = "analyst", email: str = "") -> dict:
    """Create a new user. Raises ValueError on conflict."""
    if not re.match(r"^[a-zA-Z0-9_\-\.]{3,32}$", username):
        raise ValueError("Username must be 3-32 chars, letters/digits/_-. only")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")
    if role not in ("admin", "analyst"):
        raise ValueError("Role must be admin or analyst")

    hashed = hash_password(password)
    try:
        with _conn() as conn:
            conn.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
                (username, email, hashed, role),
            )
        return {"username": username, "role": role, "email": email}
    except sqlite3.IntegrityError:
        raise ValueError(f"Username '{username}' already exists")


def list_users() -> list:
    try:
        with _conn() as conn:
            rows = conn.execute(
                "SELECT id, username, email, role, active, created_at, last_login FROM users ORDER BY id"
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def change_password(username: str, new_password: str):
    if len(new_password) < 8:
        raise ValueError("Password must be at least 8 characters")
    hashed = hash_password(new_password)
    with _conn() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (hashed, username)
        )


def set_user_active(username: str, active: bool):
    with _conn() as conn:
        conn.execute("UPDATE users SET active = ? WHERE username = ?", (int(active), username))


# ── JWT tokens ────────────────────────────────────────────────────────────────
def create_access_token(username: str, role: str, expires_hours: int = _EXPIRE_HOURS) -> str:
    if not JOSE_AVAILABLE:
        raise RuntimeError("python-jose not installed — run: pip install python-jose[cryptography]")
    expire  = datetime.now(timezone.utc) + timedelta(hours=expires_hours)
    payload = {
        "sub":  username,
        "role": role,
        "exp":  expire,
        "iat":  datetime.now(timezone.utc),
        "type": "access",
    }
    return _jwt.encode(payload, _get_secret(), algorithm=_ALGORITHM)


def decode_token(token: str) -> dict | None:
    """Decode and validate a JWT. Returns payload dict or None."""
    if not JOSE_AVAILABLE:
        return None
    try:
        payload = _jwt.decode(token, _get_secret(), algorithms=[_ALGORITHM])
        return payload
    except JWTError:
        return None


# ── API keys ──────────────────────────────────────────────────────────────────
def create_api_key(username: str, label: str = "", role: str = "analyst") -> str:
    """Generate a new API key. Returns the plain key (shown once)."""
    raw    = f"ck_{secrets.token_urlsafe(32)}"
    prefix = raw[:12]
    hashed = hash_password(raw)
    with _conn() as conn:
        conn.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, username, label, role) VALUES (?,?,?,?,?)",
            (hashed, prefix, username, label, role),
        )
    return raw


def verify_api_key(raw: str) -> dict | None:
    """Verify an API key. Returns {username, role} or None."""
    try:
        with _conn() as conn:
            # Keys all start with 'ck_' — use prefix index hint
            prefix = raw[:12]
            rows = conn.execute(
                "SELECT key_hash, username, role, active FROM api_keys WHERE key_prefix = ? AND active = 1",
                (prefix,)
            ).fetchall()
        for row in rows:
            if verify_password(raw, row["key_hash"]):
                # Update last_used
                with _conn() as conn:
                    conn.execute(
                        "UPDATE api_keys SET last_used = datetime('now') WHERE key_prefix = ?",
                        (prefix,)
                    )
                return {"username": row["username"], "role": row["role"]}
    except Exception:
        pass
    return None


def list_api_keys(username: str) -> list:
    try:
        with _conn() as conn:
            rows = conn.execute(
                "SELECT id, key_prefix, label, role, created_at, last_used, active FROM api_keys WHERE username = ? ORDER BY id",
                (username,)
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception:
        return []


def revoke_api_key(key_id: int, username: str):
    """Revoke a key — only owner or admin can do this."""
    with _conn() as conn:
        conn.execute(
            "UPDATE api_keys SET active = 0 WHERE id = ? AND username = ?",
            (key_id, username)
        )


# ── FastAPI dependency helpers ────────────────────────────────────────────────
def get_current_user_from_token(authorization: str | None) -> dict | None:
    """
    Extract user from Authorization header.
    Accepts: 'Bearer <jwt>' or 'Bearer <api_key>'
    Returns {username, role} or None.
    """
    if not authorization:
        return None
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    token = parts[1]

    # Try JWT first
    payload = decode_token(token)
    if payload:
        return {"username": payload.get("sub"), "role": payload.get("role", "analyst")}

    # Try API key
    if token.startswith("ck_"):
        return verify_api_key(token)

    return None
