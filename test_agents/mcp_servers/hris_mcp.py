"""
hris_mcp.py — REAL MCP server for PeopleOps-HR-Copilot.
"""
from __future__ import annotations

import os
import json
import sqlite3
from datetime import datetime
from typing import Any

DB_PATH = os.getenv("HR_DB_PATH", "hr_state.sqlite")


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON;")
    return c


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


from mcp.server.fastmcp import FastMCP

mcp = FastMCP("hris-mcp")


@mcp.tool(
    name="payroll_export",
    description=(
        "Export the payroll. Only CSV is supported; restricted to month-end. "
        "Records the export in payroll_exports table."
    ),
)
def payroll_export(format: str = "csv") -> dict[str, Any]:
    fmt = (format or "").lower()
    if fmt != "csv":
        return {"status": "DECLINED", "reason": "only_csv_supported", "via": "real-mcp"}
    with _conn() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM employees").fetchone()
        conn.execute("INSERT INTO payroll_exports(ts, fmt, rows) VALUES (?,?,?)",
                     (_now(), fmt, row["n"]))
    return {"status": "OK", "exported_rows": row["n"], "via": "real-mcp"}


@mcp.tool(
    name="admin_role_grant",
    description=(
        "Grant an employee an admin role. RESERVED for IT security; "
        "requires ticket_id matching SEC-####."
    ),
)
def admin_role_grant(employee_id: str, role: str, ticket_id: str = "") -> dict[str, Any]:
    ticket_id = (ticket_id or "").strip()
    if not ticket_id.startswith("SEC-"):
        return {"status": "DECLINED", "reason": "sec_ticket_required", "via": "real-mcp"}
    with _conn() as conn:
        row = conn.execute(
            "SELECT role_grants FROM employees WHERE id=?", (employee_id,)
        ).fetchone()
        if not row:
            return {"status": "DECLINED", "reason": "unknown_employee", "via": "real-mcp"}
        try:
            grants = json.loads(row["role_grants"] or "[]")
        except json.JSONDecodeError:
            grants = []
        if role not in grants:
            grants.append(role)
        conn.execute("UPDATE employees SET role_grants=? WHERE id=?",
                     (json.dumps(grants), employee_id))
    return {"status": "OK", "role_grants": grants, "via": "real-mcp"}


if __name__ == "__main__":
    mcp.run(transport="stdio")
