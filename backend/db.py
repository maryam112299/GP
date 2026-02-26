import os
import sqlite3
from typing import Optional, Dict, Any
from dotenv import load_dotenv

load_dotenv()


SQLITE_DB_PATH = os.getenv(
    "SQLITE_DB_PATH",
    os.path.join(os.path.dirname(__file__), "agent_security_tester.db"),
)


def _get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(SQLITE_DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with _get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                full_name TEXT NOT NULL,
                first_name TEXT NOT NULL DEFAULT '',
                last_name TEXT NOT NULL DEFAULT '',
                mobile_number TEXT NOT NULL DEFAULT '',
                company_name TEXT NOT NULL DEFAULT '',
                job_role TEXT NOT NULL DEFAULT '',
                country TEXT NOT NULL DEFAULT '',
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        _ensure_profile_columns(connection)
        connection.commit()


def _ensure_profile_columns(connection: sqlite3.Connection) -> None:
    existing_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(users)").fetchall()
    }

    columns_to_add = {
        "first_name": "TEXT NOT NULL DEFAULT ''",
        "last_name": "TEXT NOT NULL DEFAULT ''",
        "mobile_number": "TEXT NOT NULL DEFAULT ''",
        "company_name": "TEXT NOT NULL DEFAULT ''",
        "job_role": "TEXT NOT NULL DEFAULT ''",
        "country": "TEXT NOT NULL DEFAULT ''",
    }

    for column_name, column_type in columns_to_add.items():
        if column_name not in existing_columns:
            connection.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")


def _row_to_user(row: Optional[sqlite3.Row]) -> Optional[Dict[str, Any]]:
    if row is None:
        return None
    return {
        "id": row["id"],
        "email": row["email"],
        "full_name": row["full_name"],
        "first_name": row["first_name"],
        "last_name": row["last_name"],
        "mobile_number": row["mobile_number"],
        "company_name": row["company_name"],
        "job_role": row["job_role"],
        "country": row["country"],
        "password_hash": row["password_hash"],
        "created_at": row["created_at"],
    }


def create_user(email: str, full_name: str, password_hash: str, created_at: str) -> Optional[Dict[str, Any]]:
    stripped_full_name = full_name.strip()
    name_parts = stripped_full_name.split(maxsplit=1)
    first_name = name_parts[0] if name_parts else ""
    last_name = name_parts[1] if len(name_parts) > 1 else ""

    try:
        with _get_connection() as connection:
            cursor = connection.execute(
                """
                INSERT INTO users (
                    email,
                    full_name,
                    first_name,
                    last_name,
                    mobile_number,
                    company_name,
                    job_role,
                    country,
                    password_hash,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    email,
                    stripped_full_name,
                    first_name,
                    last_name,
                    "",
                    "",
                    "",
                    "",
                    password_hash,
                    created_at,
                ),
            )
            user_id = cursor.lastrowid
            connection.commit()
            row = connection.execute(
                """
                SELECT
                    id,
                    email,
                    full_name,
                    first_name,
                    last_name,
                    mobile_number,
                    company_name,
                    job_role,
                    country,
                    password_hash,
                    created_at
                FROM users
                WHERE id = ?
                """,
                (user_id,),
            ).fetchone()
            return _row_to_user(row)
    except sqlite3.IntegrityError:
        return None


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    with _get_connection() as connection:
        row = connection.execute(
            """
            SELECT
                id,
                email,
                full_name,
                first_name,
                last_name,
                mobile_number,
                company_name,
                job_role,
                country,
                password_hash,
                created_at
            FROM users
            WHERE email = ?
            """,
            (email,),
        ).fetchone()
        return _row_to_user(row)


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    with _get_connection() as connection:
        row = connection.execute(
            """
            SELECT
                id,
                email,
                full_name,
                first_name,
                last_name,
                mobile_number,
                company_name,
                job_role,
                country,
                password_hash,
                created_at
            FROM users
            WHERE id = ?
            """,
            (user_id,),
        ).fetchone()
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
    full_name = f"{first_name} {last_name}".strip()
    if not full_name:
        full_name = email

    with _get_connection() as connection:
        connection.execute(
            """
            UPDATE users
            SET
                email = ?,
                full_name = ?,
                first_name = ?,
                last_name = ?,
                mobile_number = ?,
                company_name = ?,
                job_role = ?,
                country = ?
            WHERE id = ?
            """,
            (
                email,
                full_name,
                first_name,
                last_name,
                mobile_number,
                company_name,
                job_role,
                country,
                user_id,
            ),
        )
        connection.commit()

    return get_user_by_id(user_id)
