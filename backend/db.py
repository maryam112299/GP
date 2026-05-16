import os
import json
import sqlite3
from typing import Optional, Dict, Any, List
from dotenv import load_dotenv

load_dotenv()

SQLITE_DB_PATH = os.getenv(
    "SQLITE_DB_PATH",
    os.path.join(os.path.dirname(__file__), "agent_security_tester.db"),
)


# ---------------------------------------------------------------------------
# Connection
# ---------------------------------------------------------------------------

def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_db() -> None:
    with _get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                email           TEXT    NOT NULL UNIQUE,
                full_name       TEXT    NOT NULL,
                first_name      TEXT    NOT NULL DEFAULT '',
                last_name       TEXT    NOT NULL DEFAULT '',
                mobile_number   TEXT    NOT NULL DEFAULT '',
                company_name    TEXT    NOT NULL DEFAULT '',
                job_role        TEXT    NOT NULL DEFAULT '',
                country         TEXT    NOT NULL DEFAULT '',
                password_hash   TEXT    NOT NULL,
                created_at      TEXT    NOT NULL
            )
            """
        )
        _ensure_user_columns(conn)

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id          INTEGER NOT NULL,
                input_text       TEXT    NOT NULL,
                output_json      TEXT    NOT NULL,
                duration_seconds REAL    NOT NULL,
                created_at       TEXT    NOT NULL,
                mode             TEXT    NOT NULL DEFAULT 'quick',
                scoring_mode     TEXT    NOT NULL DEFAULT 'cvss',
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        _ensure_analysis_columns(conn)
        conn.commit()


def _ensure_user_columns(conn: sqlite3.Connection) -> None:
    """Add any missing profile columns to the users table (migration-safe)."""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    desired = {
        "first_name":    "TEXT NOT NULL DEFAULT ''",
        "last_name":     "TEXT NOT NULL DEFAULT ''",
        "mobile_number": "TEXT NOT NULL DEFAULT ''",
        "company_name":  "TEXT NOT NULL DEFAULT ''",
        "job_role":      "TEXT NOT NULL DEFAULT ''",
        "country":       "TEXT NOT NULL DEFAULT ''",
    }
    for col, typedef in desired.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} {typedef}")


def _ensure_analysis_columns(conn: sqlite3.Connection) -> None:
    """Add any missing columns to the analyses table (migration-safe)."""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(analyses)").fetchall()}
    desired = {
        "mode":         "TEXT NOT NULL DEFAULT 'quick'",
        "scoring_mode": "TEXT NOT NULL DEFAULT 'cvss'",
    }
    for col, typedef in desired.items():
        if col not in existing:
            conn.execute(f"ALTER TABLE analyses ADD COLUMN {col} {typedef}")


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------

_USER_SELECT = """
    SELECT id, email, full_name, first_name, last_name,
           mobile_number, company_name, job_role, country,
           password_hash, created_at
    FROM users
"""


def _row_to_user(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return {
        "id":             row["id"],
        "email":          row["email"],
        "full_name":      row["full_name"],
        "first_name":     row["first_name"],
        "last_name":      row["last_name"],
        "mobile_number":  row["mobile_number"],
        "company_name":   row["company_name"],
        "job_role":       row["job_role"],
        "country":        row["country"],
        "password_hash":  row["password_hash"],
        "created_at":     row["created_at"],
    }


def create_user(
    email: str,
    full_name: str,
    password_hash: str,
    created_at: str,
) -> Optional[Dict[str, Any]]:
    name_parts = full_name.strip().split(maxsplit=1)
    first_name = name_parts[0] if name_parts else ""
    last_name  = name_parts[1] if len(name_parts) > 1 else ""

    try:
        with _get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT INTO users
                    (email, full_name, first_name, last_name,
                     mobile_number, company_name, job_role, country,
                     password_hash, created_at)
                VALUES (?, ?, ?, ?, '', '', '', '', ?, ?)
                """,
                (email, full_name.strip(), first_name, last_name, password_hash, created_at),
            )
            user_id = cursor.lastrowid
            conn.commit()
            row = conn.execute(f"{_USER_SELECT} WHERE id = ?", (user_id,)).fetchone()
            return _row_to_user(row)
    except sqlite3.IntegrityError:
        return None


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    with _get_connection() as conn:
        row = conn.execute(f"{_USER_SELECT} WHERE email = ?", (email,)).fetchone()
        return _row_to_user(row)


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with _get_connection() as conn:
        row = conn.execute(f"{_USER_SELECT} WHERE id = ?", (user_id,)).fetchone()
        return _row_to_user(row)


def update_user_profile(
    user_id: int,
    email: str,
    first_name: str,
    last_name: str,
    mobile_number: str,
    company_name: str,
    job_role: str,
    country: str,
) -> Optional[Dict[str, Any]]:
    full_name = f"{first_name} {last_name}".strip() or email
    with _get_connection() as conn:
        conn.execute(
            """
            UPDATE users
            SET email = ?, full_name = ?, first_name = ?, last_name = ?,
                mobile_number = ?, company_name = ?, job_role = ?, country = ?
            WHERE id = ?
            """,
            (email, full_name, first_name, last_name,
             mobile_number, company_name, job_role, country, user_id),
        )
        conn.commit()
    return get_user_by_id(user_id)


# ---------------------------------------------------------------------------
# Analysis record helpers
# ---------------------------------------------------------------------------

def create_analysis_record(
    user_id: int,
    input_text: str,
    output_json: str,
    duration_seconds: float,
    created_at: str,
    mode: str = "quick",
    scoring_mode: str = "cvss",
) -> Dict[str, Any]:
    with _get_connection() as conn:
        cursor = conn.execute(
            """
            INSERT INTO analyses (user_id, input_text, output_json, duration_seconds, created_at, mode, scoring_mode)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (user_id, input_text, output_json, duration_seconds, created_at, mode, scoring_mode),
        )
        analysis_id = cursor.lastrowid
        conn.commit()
        row = conn.execute(
            "SELECT id, user_id, input_text, output_json, duration_seconds, created_at, mode, scoring_mode FROM analyses WHERE id = ?",
            (analysis_id,),
        ).fetchone()

    return {
        "id":               row["id"],
        "user_id":          row["user_id"],
        "input_text":       row["input_text"],
        "output":           json.loads(row["output_json"]),
        "duration_seconds": row["duration_seconds"],
        "created_at":       row["created_at"],
        "mode":             row["mode"],
        "scoring_mode":     row["scoring_mode"],
    }


def get_analyses_by_user_id(user_id: int) -> List[Dict[str, Any]]:
    with _get_connection() as conn:
        rows = conn.execute(
            """
            SELECT id, user_id, input_text, output_json, duration_seconds, created_at, mode, scoring_mode
            FROM analyses
            WHERE user_id = ?
            ORDER BY datetime(created_at) DESC
            """,
            (user_id,),
        ).fetchall()

    return [
        {
            "id":               row["id"],
            "user_id":          row["user_id"],
            "input_text":       row["input_text"],
            "output":           json.loads(row["output_json"]),
            "duration_seconds": row["duration_seconds"],
            "created_at":       row["created_at"],
            "mode":             row["mode"],
            "scoring_mode":     row["scoring_mode"],
        }
        for row in rows
    ]
