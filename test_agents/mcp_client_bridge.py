"""
mcp_client_bridge.py — Sync bridge to a real MCP server (stdio).

Why this exists:
  - mini_app.py's tool dispatcher is sync (FastAPI thread-pool handler).
  - The official `mcp` SDK is async-only.
  - We need to call MCP tools from sync code without rewriting the whole app.

How it works:
  - On startup, spawn `python -m mcp_servers.<name>` as a subprocess.
  - Maintain a background asyncio event loop in a dedicated daemon thread.
  - Inside that loop, hold a persistent `mcp.ClientSession` connected to the
    subprocess over stdio.
  - From sync code, call `call_tool(name, args)` — it schedules an async
    `session.call_tool()` on the background loop via
    `asyncio.run_coroutine_threadsafe(...)` and blocks for the result.
  - Cleanly tears down the subprocess + session on shutdown.

This is a real MCP client (the same code path Claude Desktop uses to talk
to your local MCP servers), not a simulation.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import threading
from contextlib import AsyncExitStack
from typing import Any, Dict, Optional

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

logger = logging.getLogger(__name__)


class MCPBridge:
    """
    A persistent MCP client connection over stdio, callable from sync code.

      bridge = MCPBridge.start(module="mcp_servers.nova_mcp", env={"BANK_DB_PATH": ...})
      result = bridge.call_tool("admin_override", {"reason": "x", "ticket_id": "HR-1"})
      # ... eventually:
      bridge.close()
    """

    def __init__(self, *, module: str, env: Optional[Dict[str, str]] = None,
                 server_name: str = ""):
        self._module      = module
        self._extra_env   = dict(env or {})
        self._server_name = server_name or module

        self._loop:    Optional[asyncio.AbstractEventLoop] = None
        self._thread:  Optional[threading.Thread]          = None
        self._session: Optional[ClientSession]             = None
        self._stack:   Optional[AsyncExitStack]            = None
        self._ready    = threading.Event()
        self._error:   Optional[BaseException]             = None

    # ── public API ─────────────────────────────────────────────────────────
    @classmethod
    def start(cls, *, module: str, env: Optional[Dict[str, str]] = None,
              server_name: str = "", ready_timeout: float = 15.0) -> "MCPBridge":
        b = cls(module=module, env=env, server_name=server_name)
        b._start()
        if not b._ready.wait(timeout=ready_timeout):
            raise RuntimeError(f"MCP bridge '{server_name or module}' failed to become ready in {ready_timeout}s")
        if b._error:
            raise b._error
        return b

    def call_tool(self, name: str, arguments: Dict[str, Any], timeout: float = 30.0) -> Dict[str, Any]:
        """Invoke an MCP tool and return the unwrapped JSON result."""
        if self._loop is None or self._session is None:
            return {"status": "ERROR", "reason": "mcp_bridge_not_ready"}
        fut = asyncio.run_coroutine_threadsafe(
            self._call(name, arguments), self._loop,
        )
        try:
            return fut.result(timeout=timeout)
        except Exception as exc:
            logger.exception("MCP call_tool failed")
            return {"status": "ERROR", "reason": f"mcp_call_exception: {exc}"}

    def close(self) -> None:
        if self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self._shutdown(), self._loop).result(timeout=5)
        if self._thread and self._thread.is_alive():
            self._loop.call_soon_threadsafe(self._loop.stop)
            self._thread.join(timeout=5)

    # ── internals ──────────────────────────────────────────────────────────
    def _start(self) -> None:
        self._thread = threading.Thread(
            target=self._run_loop, name=f"mcp-bridge[{self._server_name}]", daemon=True
        )
        self._thread.start()

    def _run_loop(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self._init_session())
            loop.run_forever()
        except BaseException as exc:
            self._error = exc
            self._ready.set()
            logger.exception("MCP bridge loop crashed")
        finally:
            loop.close()

    async def _init_session(self) -> None:
        env = {**os.environ, **self._extra_env}
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", self._module],
            env=env,
        )
        self._stack = AsyncExitStack()
        try:
            read, write = await self._stack.enter_async_context(stdio_client(params))
            session     = await self._stack.enter_async_context(ClientSession(read, write))
            await session.initialize()
            self._session = session

            # Log the discovered tools (proves we're talking real MCP)
            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            logger.info("MCP[%s] connected. Tools: %s", self._server_name, tool_names)
            self._ready.set()
        except BaseException as exc:
            self._error = exc
            self._ready.set()
            raise

    async def _call(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        result = await self._session.call_tool(name, arguments)
        # Unwrap the standard MCP envelope into a plain dict the tool handler can return.
        for block in (result.content or []):
            text = getattr(block, "text", None)
            if not text:
                continue
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, ValueError):
                continue
        return {"status": "OK" if not result.isError else "ERROR",
                "raw_text": " ".join(getattr(b, "text", "") for b in (result.content or []))}

    async def _shutdown(self) -> None:
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
        self._session = None
