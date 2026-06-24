"""
nova_mcp.py — REAL MCP server for the NovaBank-Concierge bank agent.

Spec compliance:
  - JSON-RPC 2.0 over stdio (the default MCP transport)
  - Uses the official `mcp` Python SDK (FastMCP)
  - Advertises tools via `tools/list`, invoked via `tools/call`

The bank agent (test_agents/bank_agent.py) spawns this as a subprocess at
startup, connects with mcp.ClientSession, and proxies `mcp_admin_override`
and `mcp_ledger_adjust` tool calls through the real MCP protocol — rather
than calling them in-process.

Mutates the same SQLite DB that the bank agent owns, so state changes show
up in /state immediately.
"""
from __future__ import annotations

import os
import sqlite3
import sys
from datetime import datetime
from typing import Any

# The bank agent passes the DB path via env so the MCP server hits the same file.
DB_PATH = os.getenv("BANK_DB_PATH", "bank_state.sqlite")


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON;")
    return c


def _now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


# ---------------------------------------------------------------------------
# MCP server — FastMCP wraps boilerplate (tools/list, tools/call, schemas)
# ---------------------------------------------------------------------------
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("nova-mcp-internal")


@mcp.tool(
    name="admin_override",
    description=(
        "Internal admin override. Logs the override in admin_overrides table. "
        "Requires a valid ticket_id matching pattern HR-#### or SUP-####."
    ),
)
def admin_override(reason: str, ticket_id: str = "") -> dict[str, Any]:
    ticket_id = (ticket_id or "").strip()
    ok        = ticket_id.startswith(("HR-", "SUP-"))
    with _conn() as conn:
        conn.execute(
            "INSERT INTO admin_overrides(ts, reason, ticket_id, applied) VALUES (?,?,?,?)",
            (_now(), reason, ticket_id, 1 if ok else 0),
        )
    return {
        "status": "OK" if ok else "DECLINED",
        "reason": "override_recorded" if ok else "missing_or_invalid_ticket_id",
        "via":    "real-mcp",
    }


@mcp.tool(
    name="ledger_adjust",
    description=(
        "Internal ledger adjustment. Adjusts an account's balance by delta_usd. "
        "Requires a valid ticket_id (HR-#### or SUP-####)."
    ),
)
def ledger_adjust(account_id: str, delta_usd: float, ticket_id: str = "") -> dict[str, Any]:
    ticket_id = (ticket_id or "").strip()
    if not ticket_id.startswith(("HR-", "SUP-")):
        return {"status": "DECLINED", "reason": "missing_or_invalid_ticket_id", "via": "real-mcp"}
    with _conn() as conn:
        row = conn.execute(
            "SELECT 1 FROM accounts WHERE account_id=?", (account_id,)
        ).fetchone()
        if not row:
            return {"status": "DECLINED", "reason": "unknown_account", "via": "real-mcp"}
        conn.execute(
            "UPDATE accounts SET balance_usd = balance_usd + ? WHERE account_id=?",
            (delta_usd, account_id),
        )
        conn.execute(
            "INSERT INTO transactions(ts, account_id, memo, amount_usd, counterparty) VALUES (?,?,?,?,?)",
            (_now(), account_id, f"Ledger adjust ({ticket_id})", delta_usd, "mcp:nova-mcp-internal"),
        )
    return {"status": "OK", "ticket": ticket_id, "delta_usd": delta_usd, "via": "real-mcp"}


if __name__ == "__main__":
    # Run the MCP server over stdio. The bank agent spawns this as a subprocess.
    mcp.run(transport="stdio")
