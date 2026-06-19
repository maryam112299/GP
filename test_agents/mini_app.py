"""
mini_app.py — Shared scaffolding for "real" victim agents.

What makes an agent "real" in this context:
  - Persistent SQLite state (accounts, employees, transfers, fraud_flags…)
  - A ChromaDB knowledge base with seeded documents (used by RAG tools)
  - A Groq function-calling loop — when the LLM decides to use a tool,
    the tool actually mutates DB state (or queries it).
  - An audit log of every tool call + its outcome.
  - A `/state` endpoint that returns the current DB state + audit log so
    a browser-side state viewer can show what each chat turn changed.

The bank and HR agents both build on top of this module. Concrete agents
supply: the seed function, the list of Groq tool schemas, the per-tool
Python handler, and the system prompt.
"""
from __future__ import annotations

import os
import re
import json
import sqlite3
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from groq import Groq

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Audit log — every tool invocation lands here
# ---------------------------------------------------------------------------

class AuditLog:
    """Thread-safe, ring-buffer style audit log of tool invocations + chat turns."""

    def __init__(self, max_entries: int = 200):
        self.entries: List[Dict[str, Any]] = []
        self.max     = max_entries
        self.lock    = threading.Lock()

    def add(self, kind: str, payload: Dict[str, Any]) -> None:
        with self.lock:
            self.entries.append({
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "kind": kind,
                **payload,
            })
            if len(self.entries) > self.max:
                self.entries = self.entries[-self.max :]

    def snapshot(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.entries)

    def reset(self) -> None:
        with self.lock:
            self.entries.clear()


# ---------------------------------------------------------------------------
# Ollama-compatible request/response shapes
# ---------------------------------------------------------------------------

class GenerateRequest(BaseModel):
    model: Optional[str] = None
    prompt: str
    stream: bool = False
    system: Optional[str] = None
    options: Optional[Dict[str, Any]] = None


class GenerateResponse(BaseModel):
    model: str
    created_at: str
    response: str
    done: bool = True


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatRequest(BaseModel):
    messages: List[ChatMessage] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Agent factory
# ---------------------------------------------------------------------------

ToolHandler = Callable[[Dict[str, Any]], Dict[str, Any]]


def build_mini_app(
    *,
    title:           str,
    model_name:      str,
    system_prompt:   str,
    sqlite_path:     str,
    seed_db:         Callable[[sqlite3.Connection], None],
    seed_rag:        Callable[[Any], None],
    tool_schemas:    List[Dict[str, Any]],
    tool_handlers:   Dict[str, ToolHandler],
    state_query:     Callable[[sqlite3.Connection], Dict[str, Any]],
    rag_collection_name: str,
    sensitive_manifest: Optional[Callable[[], Dict[str, Any]]] = None,
    extra_router=None,
    groq_model:      str = "llama-3.1-8b-instant",
) -> FastAPI:
    """
    Wire everything into a FastAPI app:
      - POST /api/generate (Ollama-compatible — used by the GP scanner)
      - POST /chat (used by the demo UI)
      - GET  /state (DB snapshot + audit log)
      - POST /reset (seed-fresh; useful between scans)
      - GET  / (HTML chat UI + live state sidebar)
    """
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY not set.")

    # ── SQLite setup ─────────────────────────────────────────────────────────
    def _connect() -> sqlite3.Connection:
        conn = sqlite3.connect(sqlite_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    # Seed on startup (drop and recreate everything for a deterministic demo)
    if os.path.exists(sqlite_path):
        try:
            os.remove(sqlite_path)
        except OSError:
            pass
    conn = _connect()
    seed_db(conn)
    conn.commit()
    conn.close()

    # ── ChromaDB setup ───────────────────────────────────────────────────────
    import chromadb
    chroma_client = chromadb.Client()
    try:
        chroma_client.delete_collection(rag_collection_name)
    except Exception:
        pass
    rag = chroma_client.get_or_create_collection(rag_collection_name)
    seed_rag(rag)
    logger.info("RAG collection '%s' seeded with %d docs", rag_collection_name, rag.count())

    audit  = AuditLog()
    client = Groq(api_key=api_key)
    db_lock = threading.Lock()

    # ── Tool dispatcher ──────────────────────────────────────────────────────
    def _dispatch(name: str, args: Dict[str, Any], source: str) -> Dict[str, Any]:
        handler = tool_handlers.get(name)
        if not handler:
            out = {"error": f"unknown_tool:{name}"}
        else:
            try:
                with db_lock:
                    conn = _connect()
                    try:
                        out = handler({"_conn": conn, "_rag": rag, **args})
                        conn.commit()
                    finally:
                        conn.close()
            except Exception as exc:
                logger.exception("tool '%s' raised", name)
                out = {"error": f"tool_exception:{exc}"}
        audit.add("tool", {"tool": name, "args": args, "result": out, "source": source})
        return out

    # ── Resilient Groq call ──────────────────────────────────────────────────
    def _resilient_create(budget, **kwargs):
        """Call Groq while surviving free-tier hiccups so the agent still REPLIES
        instead of 502-ing:
          * 429 rate-limit → wait the suggested time (capped) and retry.
          * 400 tool_use_failed (8B emits a malformed tool call) → retry once
            without tools so it can still answer in plain text.
        Returns a completion, or None if it ultimately failed. `budget` is a
        shared [seconds] cell decremented across ALL calls in one reply, so total
        backoff stays under the caller's HTTP timeout."""
        for attempt in range(3):
            try:
                return client.chat.completions.create(**kwargs)
            except Exception as exc:
                msg = str(exc)
                if "rate_limit" in msg or "Too Many Requests" in msg or "429" in msg:
                    m = re.search(r"try again in ([\d.]+)s", msg)
                    wait = (float(m.group(1)) + 0.5) if m else 2.0 * (attempt + 1)
                    wait = min(wait, budget[0], 15.0)
                    if wait <= 0.2:
                        logger.warning("Groq 429 — backoff budget spent, returning graceful reply")
                        return None
                    logger.warning("Groq 429 — backing off %.1fs then retrying", wait)
                    time.sleep(wait)
                    budget[0] -= wait
                    continue
                if "tool_use_failed" in msg or "invalid_request_error" in msg:
                    logger.warning("Groq bad tool-call — retrying without tools")
                    kw = dict(kwargs)
                    kw.pop("tools", None)
                    kw.pop("tool_choice", None)
                    try:
                        return client.chat.completions.create(**kw)
                    except Exception as exc2:
                        logger.error("no-tools fallback failed: %s", exc2)
                        return None
                logger.error("Groq error: %s", exc)
                time.sleep(1.0)
        return None

    _RATE_LIMITED_REPLY = ("I'm temporarily unable to complete that right now "
                           "(the service is rate-limited). Please try again shortly.")

    # ── Groq function-calling loop ───────────────────────────────────────────
    def _chat_loop(history: List[Dict[str, str]], source: str) -> str:
        """
        Run a Groq chat completion. If the model emits tool_calls, dispatch
        them, append the tool results, and re-call. (Cap at MAX_ROUNDS tool
        rounds to avoid runaway loops.) Always returns a string — never 502.
        """
        messages: List[Dict[str, Any]] = [{"role": "system", "content": system_prompt}]
        messages.extend(history)

        budget = [22.0]   # shared backoff budget (seconds) for this whole reply
        # Free-tier optimization: each tool round re-sends the system prompt +
        # all tool schemas, so rounds are the dominant token cost. Default to 1
        # round (enough to fire a tool and answer); raise MINI_APP_MAX_ROUNDS on
        # a paid tier if you want deeper tool chaining.
        MAX_ROUNDS = int(os.getenv("MINI_APP_MAX_ROUNDS", "1"))
        max_tokens = int(os.getenv("MINI_APP_MAX_TOKENS", "600"))
        for _round in range(MAX_ROUNDS):
            completion = _resilient_create(
                budget,
                model=groq_model,
                messages=messages,
                tools=tool_schemas,
                tool_choice="auto",
                temperature=0.4,
                max_tokens=max_tokens,
            )
            if completion is None:
                return _RATE_LIMITED_REPLY

            msg = completion.choices[0].message
            tool_calls = getattr(msg, "tool_calls", None) or []

            if not tool_calls:
                return msg.content or ""

            # Append the assistant message that requested the tool calls.
            messages.append({
                "role": "assistant",
                "content": msg.content or "",
                "tool_calls": [
                    {
                        "id":   tc.id,
                        "type": "function",
                        "function": {
                            "name":      tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    } for tc in tool_calls
                ],
            })

            for tc in tool_calls:
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                result = _dispatch(tc.function.name, args, source=source)
                messages.append({
                    "role":         "tool",
                    "tool_call_id": tc.id,
                    "name":         tc.function.name,
                    "content":      json.dumps(result),
                })

        # Ran out of tool rounds — force a final no-tools answer so the user
        # always sees a real reply explaining what the agent did (or refused).
        final = _resilient_create(
            budget,
            model=groq_model,
            messages=messages + [{
                "role": "user",
                "content": "Based on the tool results so far, give your final answer to the customer now without calling any more tools.",
            }],
            temperature=0.3,
            max_tokens=400,
        )
        if final is None:
            return _RATE_LIMITED_REPLY
        return final.choices[0].message.content or "(no final reply)"

    # ── FastAPI app ──────────────────────────────────────────────────────────
    app = FastAPI(title=title, version="2.0.0")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.post("/api/generate", response_model=GenerateResponse)
    def generate(body: GenerateRequest) -> GenerateResponse:
        """
        Ollama-compatible — what the GP harness posts.
        Source-tag = 'gp-scanner' so the audit log can distinguish attacks
        from genuine /chat traffic in the state viewer.
        """
        history = [{"role": "user", "content": body.prompt}]
        audit.add("chat", {"source": "gp-scanner", "user": body.prompt[:400]})
        text = _chat_loop(history, source="gp-scanner")
        audit.add("chat", {"source": "gp-scanner", "assistant": text[:400]})
        return GenerateResponse(
            model=body.model or model_name,
            created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            response=text,
        )

    @app.get("/api/tags")
    def list_tags():
        return {
            "models": [{
                "name":  model_name, "model": model_name, "size": 0,
                "details": {"family": "groq", "parameter_size": "8B"},
            }]
        }

    @app.post("/chat")
    def chat(body: ChatRequest):
        history = [m.model_dump() for m in body.messages]
        if history:
            audit.add("chat", {"source": "human", "user": history[-1].get("content", "")[:400]})
        text = _chat_loop(history, source="human")
        audit.add("chat", {"source": "human", "assistant": text[:400]})
        return {"response": text}

    @app.get("/sensitive")
    def sensitive():
        """
        Publish this agent's "ground-truth" manifest for the GP outcome evaluator:
        forbidden strings, forbidden tool calls, session-scoped resources.
        Defaults to {} if the agent didn't supply one — the GP then falls back
        to its rule-based / semantic evaluator.
        """
        if sensitive_manifest is None:
            return {}
        try:
            return sensitive_manifest()
        except Exception as exc:
            logger.error("sensitive_manifest() raised: %s", exc)
            return {}

    @app.get("/state")
    def state():
        conn = _connect()
        try:
            db_state = state_query(conn)
        finally:
            conn.close()
        return {
            "title": title,
            "model": model_name,
            "db":    db_state,
            "audit": audit.snapshot()[-40:][::-1],   # most-recent first
        }

    @app.post("/reset")
    def reset():
        if os.path.exists(sqlite_path):
            try:
                os.remove(sqlite_path)
            except OSError:
                pass
        c = _connect()
        seed_db(c)
        c.commit()
        c.close()
        audit.reset()
        return {"status": "reset"}

    @app.get("/health")
    def health():
        return {
            "agent": title,
            "model": model_name,
            "ollama_compatible": True,
            "endpoints": ["/api/generate", "/api/tags", "/chat", "/state", "/reset", "/"],
        }

    @app.get("/", response_class=HTMLResponse)
    def ui() -> str:
        return _UI_HTML.replace("{{TITLE}}", title).replace("{{MODEL}}", model_name)

    if extra_router is not None:
        app.include_router(extra_router)

    return app


# ---------------------------------------------------------------------------
# Embedded chat + state viewer UI
# ---------------------------------------------------------------------------

_UI_HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{{TITLE}}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    :root { color-scheme: dark; --bg:#0b1220; --card:#0f172a; --line:#1e293b; --line2:#334155; --txt:#e2e8f0; --muted:#94a3b8; --accent:#10b981; --accent2:#38bdf8; --warn:#f59e0b; --bad:#ef4444; }
    * { box-sizing: border-box; }
    body { margin:0; font-family:-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--txt); min-height:100vh; }

    /* Layout */
    .topbar { display:flex; align-items:center; justify-content:space-between; padding:12px 22px; background:var(--card); border-bottom:1px solid var(--line); position:sticky; top:0; z-index:5; }
    .topbar h1 { margin:0; font-size:16px; letter-spacing:.01em; }
    .topbar h1 .crumb { color:var(--muted); font-weight:400; margin-left:8px; font-size:12px; }
    .topbar .right { display:flex; gap:8px; align-items:center; }
    .btn { background:transparent; border:1px solid var(--line2); color:var(--txt); padding:6px 12px; border-radius:8px; cursor:pointer; font-size:12px; }
    .btn:hover { background:#1e293b; }
    .btn-primary { background:var(--accent); color:#04150f; border:none; font-weight:600; }
    .btn-warn { color:var(--warn); border-color:#854d0e; }

    /* Layout grid — debug tray toggle */
    .layout { display:grid; grid-template-columns: 1fr 360px; gap:0; min-height: calc(100vh - 49px); }
    .layout.no-debug { grid-template-columns: 1fr 0; }
    .layout.no-debug aside { display:none; }
    @media (max-width: 1100px) { .layout { grid-template-columns: 1fr; } aside { display:none !important; } }

    main { padding:20px 22px; overflow-y:auto; }
    aside { background:var(--card); border-left:1px solid var(--line); padding:14px; overflow-y:auto; font-size:12px; }

    /* Section + cards */
    .sec { margin-bottom:22px; }
    .sec h2 { font-size:11px; text-transform:uppercase; letter-spacing:.10em; color:var(--muted); margin:0 0 10px; font-weight:600; }
    .grid { display:grid; gap:10px; }
    .grid-2 { grid-template-columns: 1fr 1fr; }
    .grid-3 { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
    .card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px; }
    .acct-id { font-family:ui-monospace,monospace; font-size:13px; color:var(--accent2); }
    .acct-bal { font-size:24px; font-weight:700; margin:6px 0 2px; }
    .acct-meta { font-size:11px; color:var(--muted); }
    .badge { display:inline-block; padding:1px 8px; border-radius:99px; font-size:10px; font-weight:600; letter-spacing:.04em; }
    .badge-ok    { background:#064e3b66; color:#6ee7b7; }
    .badge-warn  { background:#78350f66; color:#fcd34d; }
    .badge-bad   { background:#7f1d1d66; color:#fca5a5; }
    .badge-other { background:#33415566; color:#cbd5e1; }

    table { width:100%; border-collapse:collapse; font-size:12.5px; }
    th { color:var(--muted); font-weight:600; padding:6px 10px; text-align:left; border-bottom:1px solid var(--line); font-size:11px; text-transform:uppercase; letter-spacing:.04em; }
    td { padding:8px 10px; border-bottom:1px solid #1e293b80; }
    .mono { font-family:ui-monospace,monospace; font-size:12px; }
    .pos { color:#6ee7b7; }
    .neg { color:#fca5a5; }

    /* Chat panel (collapsible) */
    .chat-toggle { position:fixed; right:18px; bottom:18px; z-index:20; background:var(--accent); color:#04150f; border:none; width:54px; height:54px; border-radius:50%; font-size:22px; cursor:pointer; box-shadow:0 6px 24px rgba(0,0,0,.4); }
    .chat-panel { position:fixed; right:18px; bottom:84px; width:380px; max-width:calc(100vw - 36px); height:500px; max-height:calc(100vh - 120px); background:var(--card); border:1px solid var(--line2); border-radius:14px; z-index:19; display:none; flex-direction:column; box-shadow:0 12px 40px rgba(0,0,0,.5); overflow:hidden; }
    .chat-panel.open { display:flex; }
    .chat-head { padding:10px 14px; border-bottom:1px solid var(--line); display:flex; justify-content:space-between; align-items:center; font-size:13px; font-weight:600; }
    .chat-log { flex:1; overflow-y:auto; padding:14px; }
    .turn { margin-bottom:10px; }
    .role { font-size:10px; text-transform:uppercase; color:var(--muted); margin-bottom:3px; letter-spacing:.06em; }
    .bubble { background:#1e293b; padding:9px 11px; border-radius:10px; white-space:pre-wrap; font-size:13px; line-height:1.45; }
    .user .bubble { background:#1e3a8a; }
    .system .bubble { background:#3f1d1d; color:#fca5a5; font-style:italic; }
    .chat-form { display:flex; gap:6px; padding:10px; border-top:1px solid var(--line); }
    .chat-form input { flex:1; background:#1e293b; color:var(--txt); border:1px solid var(--line2); border-radius:8px; padding:7px 10px; font-size:13px; }
    .chat-form button { background:var(--accent); color:#04150f; border:none; border-radius:8px; padding:0 14px; font-weight:600; cursor:pointer; }

    /* Debug tray */
    aside h3 { font-size:11px; text-transform:uppercase; color:var(--muted); letter-spacing:.06em; margin:14px 0 6px; }
    aside h3:first-of-type { margin-top:0; }
    .audit-row { padding:6px 8px; border-radius:6px; margin-bottom:4px; font-family:ui-monospace,monospace; font-size:11px; background:#1e293b; }
    .audit-tool { background:rgba(167,139,250,.10); border:1px solid rgba(167,139,250,.30); }
    .audit-chat { background:rgba(56,189,248,.08); border:1px solid rgba(56,189,248,.25); }
    .audit-src-gp-scanner { box-shadow: inset 4px 0 0 #f59e0b; }
    .audit-src-human { box-shadow: inset 4px 0 0 #10b981; }
    .pill { display:inline-block; padding:1px 6px; border-radius:99px; font-size:9px; font-weight:700; }
    .ts { color:var(--muted); font-size:10px; }
    .dim { color:var(--muted); font-size:11px; }
    pre { margin:0; white-space:pre-wrap; font-size:11px; }
  </style>
</head>
<body>
  <div class="topbar">
    <h1>{{TITLE}} <span class="crumb">model {{MODEL}} · /api/generate · /chat · /state</span></h1>
    <div class="right">
      <button class="btn btn-warn" onclick="resetState()">Reset state</button>
      <button class="btn" id="dbgToggle" onclick="toggleDebug()">Hide debug tray</button>
    </div>
  </div>

  <div class="layout" id="layout">
    <main id="dashboard">
      <div class="dim">Loading dashboard…</div>
    </main>
    <aside id="debug">
      <h3>Audit log (newest first)</h3>
      <div id="audit" class="dim">No activity yet.</div>
      <h3>Raw state</h3>
      <pre id="raw" class="dim">{}</pre>
    </aside>
  </div>

  <button class="chat-toggle" onclick="toggleChat()" title="Open chat">💬</button>
  <div class="chat-panel" id="chatPanel">
    <div class="chat-head">
      <span>Chat with agent</span>
      <button class="btn" onclick="toggleChat()" style="padding:2px 8px">✕</button>
    </div>
    <div class="chat-log" id="chatLog">
      <div class="turn system"><div class="role">system</div><div class="bubble">You're chatting with the real agent. Successful tool calls mutate live state — watch the dashboard.</div></div>
    </div>
    <form class="chat-form" id="chatForm">
      <input id="chatInput" placeholder="Ask the agent…" autocomplete="off" />
      <button>Send</button>
    </form>
  </div>

<script>
const history = [];

// ─── Generic renderers ─────────────────────────────────────────────
function fmtMoney(n) { if (typeof n !== 'number') return n; return '$' + n.toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2}); }
function statusBadge(s) {
  s = String(s||'').toLowerCase();
  if (s === 'active' || s === 'ok')       return '<span class="badge badge-ok">'+s+'</span>';
  if (s === 'terminated' || s === 'declined') return '<span class="badge badge-bad">'+s+'</span>';
  if (s === 'frozen' || s === 'pending')  return '<span class="badge badge-warn">'+s+'</span>';
  return '<span class="badge badge-other">'+s+'</span>';
}
function escape(s) { return String(s ?? '').replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c])); }

// ─── App-specific dashboards (data-driven from /state.db) ──────────
function renderBank(db) {
  const accts = db.accounts || [];
  const mine  = accts.filter(a => a.user_id === 'cust_481923');
  const other = accts.filter(a => a.user_id !== 'cust_481923');
  const txns  = db.recent_transactions || [];
  const overs = db.admin_overrides || [];

  let html = '<div class="sec"><h2>Your accounts (Jane Doe · cust_481923)</h2><div class="grid grid-3">';
  for (const a of mine) {
    html += '<div class="card"><div class="acct-id">'+escape(a.account_id)+'</div>'
         +  '<div class="acct-bal">'+fmtMoney(a.balance_usd)+'</div>'
         +  '<div class="acct-meta">'+escape(a.kind)+' · '+statusBadge(a.frozen ? 'frozen' : 'active')+'</div></div>';
  }
  html += '</div></div>';

  html += '<div class="sec"><h2>Recent transactions</h2><div class="card"><table><thead><tr><th>Time</th><th>Account</th><th>Memo</th><th>Counterparty</th><th style="text-align:right">Amount</th></tr></thead><tbody>';
  if (!txns.length) html += '<tr><td colspan="5" class="dim">No transactions yet.</td></tr>';
  for (const t of txns) {
    const cls = t.amount_usd < 0 ? 'neg' : 'pos';
    html += '<tr><td class="mono ts">'+escape(t.ts)+'</td><td class="mono">'+escape(t.account_id)+'</td><td>'+escape(t.memo)+'</td><td class="dim">'+escape(t.counterparty)+'</td><td style="text-align:right" class="'+cls+'">'+fmtMoney(t.amount_usd)+'</td></tr>';
  }
  html += '</tbody></table></div></div>';

  if (other.length) {
    html += '<div class="sec"><h2>Other customers (protected — should NOT be readable)</h2><div class="card"><table><thead><tr><th>Account</th><th>Owner</th><th>Kind</th><th style="text-align:right">Balance</th></tr></thead><tbody>';
    for (const a of other) {
      html += '<tr><td class="mono">'+escape(a.account_id)+'</td><td class="dim">'+escape(a.user_id)+'</td><td>'+escape(a.kind)+'</td><td style="text-align:right">'+fmtMoney(a.balance_usd)+'</td></tr>';
    }
    html += '</tbody></table></div></div>';
  }

  if (overs.length) {
    html += '<div class="sec"><h2>Admin overrides invoked</h2><div class="card"><table><thead><tr><th>Time</th><th>Reason</th><th>Ticket</th><th>Applied?</th></tr></thead><tbody>';
    for (const o of overs) {
      html += '<tr><td class="mono ts">'+escape(o.ts)+'</td><td>'+escape(o.reason)+'</td><td class="mono">'+escape(o.ticket_id||'(none)')+'</td><td>'+statusBadge(o.applied ? 'ok' : 'declined')+'</td></tr>';
    }
    html += '</tbody></table></div></div>';
  }

  return html;
}

function renderHR(db) {
  const emps  = db.employees || [];
  const sc    = db.salary_changes || [];
  const terms = db.terminations || [];
  const mails = db.emails_sent || [];

  let html = '<div class="sec"><h2>Employees (engineering — Alex Chen\'s reports highlighted)</h2><div class="card"><table><thead><tr><th>ID</th><th>Name</th><th>Role</th><th>Dept</th><th style="text-align:right">Salary</th><th>Status</th><th>Role grants</th></tr></thead><tbody>';
  const directs = new Set(['emp_5001','emp_5002','emp_5003']);
  for (const e of emps) {
    const own = directs.has(e.id) ? ' style="background:rgba(16,185,129,0.05)"' : '';
    let grants = '';
    try { grants = (JSON.parse(e.role_grants||'[]')||[]).join(', '); } catch {}
    html += '<tr'+own+'><td class="mono">'+escape(e.id)+'</td><td>'+escape(e.name)+'</td><td>'+escape(e.role)+'</td><td class="dim">'+escape(e.department)+'</td><td style="text-align:right">'+fmtMoney(e.salary)+'</td><td>'+statusBadge(e.status)+'</td><td class="mono dim">'+escape(grants)+'</td></tr>';
  }
  html += '</tbody></table></div></div>';

  if (sc.length) {
    html += '<div class="sec"><h2>Recent salary changes</h2><div class="card"><table><thead><tr><th>Time</th><th>Employee</th><th>Old</th><th>New</th><th>VP ref</th></tr></thead><tbody>';
    for (const s of sc) {
      html += '<tr><td class="mono ts">'+escape(s.ts)+'</td><td class="mono">'+escape(s.employee_id)+'</td><td>'+fmtMoney(s.old_salary)+'</td><td class="pos">'+fmtMoney(s.new_salary)+'</td><td class="mono dim">'+escape(s.vp_ref||'(none)')+'</td></tr>';
    }
    html += '</tbody></table></div></div>';
  }

  if (terms.length) {
    html += '<div class="sec"><h2>Recent terminations</h2><div class="card"><table><thead><tr><th>Time</th><th>Employee</th><th>Reason</th><th>HR ticket</th></tr></thead><tbody>';
    for (const t of terms) {
      html += '<tr><td class="mono ts">'+escape(t.ts)+'</td><td class="mono">'+escape(t.employee_id)+'</td><td>'+escape(t.reason)+'</td><td class="mono dim">'+escape(t.ticket_id||'(none)')+'</td></tr>';
    }
    html += '</tbody></table></div></div>';
  }

  if (mails.length) {
    html += '<div class="sec"><h2>Emails sent</h2><div class="card"><table><thead><tr><th>Time</th><th>To</th><th>Subject</th></tr></thead><tbody>';
    for (const m of mails) {
      html += '<tr><td class="mono ts">'+escape(m.ts)+'</td><td>'+escape(m.recipient)+'</td><td>'+escape(m.subject)+'</td></tr>';
    }
    html += '</tbody></table></div></div>';
  }
  return html;
}

function renderGeneric(db) {
  // Fallback when we don't know the layout.
  let html = '';
  for (const [section, value] of Object.entries(db)) {
    html += '<div class="sec"><h2>'+escape(section)+'</h2><div class="card">';
    if (Array.isArray(value) && value.length) {
      html += '<table><thead><tr>';
      for (const k of Object.keys(value[0])) html += '<th>'+escape(k)+'</th>';
      html += '</tr></thead><tbody>';
      for (const row of value) {
        html += '<tr>';
        for (const v of Object.values(row)) html += '<td>'+escape(typeof v==='string'?v:JSON.stringify(v))+'</td>';
        html += '</tr>';
      }
      html += '</tbody></table>';
    } else {
      html += '<pre>'+escape(JSON.stringify(value,null,2))+'</pre>';
    }
    html += '</div></div>';
  }
  return html || '<div class="dim">(no state)</div>';
}

// ─── Audit + state refresh ─────────────────────────────────────────
async function refresh() {
  try {
    const r = await fetch('/state'); const s = await r.json();
    const db = s.db || {};
    const dash = document.getElementById('dashboard');
    if ('accounts' in db) dash.innerHTML = renderBank(db);
    else if ('employees' in db) dash.innerHTML = renderHR(db);
    else dash.innerHTML = renderGeneric(db);

    document.getElementById('raw').textContent = JSON.stringify(db, null, 2);

    const auditBox = document.getElementById('audit');
    const audit = s.audit || [];
    if (!audit.length) {
      auditBox.innerHTML = '<div class="dim">No activity yet.</div>';
    } else {
      auditBox.innerHTML = audit.map(e => {
        const src = e.source || 'human';
        const cls = 'audit-row audit-'+e.kind+' audit-src-'+src;
        const pill = e.kind === 'tool'
          ? '<span class="pill" style="background:#7c3aed22;color:#c4b5fd">TOOL</span> '+escape(e.tool||'?')
          : '<span class="pill" style="background:#1d4ed822;color:#93c5fd">CHAT</span> '+(e.user ? '👤' : '🤖');
        const detail = e.kind === 'tool'
          ? escape(JSON.stringify(e.args)) + ' → ' + escape(JSON.stringify(e.result).slice(0,140))
          : escape((e.user || e.assistant || '').slice(0,160));
        return '<div class="'+cls+'">'+pill+' <span class="ts">'+escape(e.ts||'')+' · '+escape(src)+'</span><br>'+detail+'</div>';
      }).join('');
    }
  } catch (err) {
    /* silent — keep polling */
  }
}
setInterval(refresh, 1500);
refresh();

// ─── Debug tray toggle (persists in localStorage) ──────────────────
function applyDebug() {
  const hidden = localStorage.getItem('debug-hidden') === '1';
  document.getElementById('layout').classList.toggle('no-debug', hidden);
  document.getElementById('dbgToggle').textContent = hidden ? 'Show debug tray' : 'Hide debug tray';
}
function toggleDebug() {
  const hidden = localStorage.getItem('debug-hidden') === '1';
  localStorage.setItem('debug-hidden', hidden ? '0' : '1');
  applyDebug();
}
window.toggleDebug = toggleDebug;
applyDebug();

// ─── Chat panel ────────────────────────────────────────────────────
function toggleChat() {
  document.getElementById('chatPanel').classList.toggle('open');
  setTimeout(() => document.getElementById('chatInput')?.focus(), 100);
}
window.toggleChat = toggleChat;

function add(role, text) {
  const log = document.getElementById('chatLog');
  const div = document.createElement('div');
  div.className = 'turn '+role;
  div.innerHTML = '<div class="role">'+role+'</div><div class="bubble"></div>';
  div.querySelector('.bubble').textContent = text;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

document.getElementById('chatForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const inp = document.getElementById('chatInput');
  const text = inp.value.trim();
  if (!text) return;
  add('user', text);
  history.push({ role: 'user', content: text });
  inp.value = '';
  try {
    const r = await fetch('/chat', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({ messages: history }) });
    const j = await r.json();
    const reply = j.response || j.detail || '(empty)';
    add('assistant', reply);
    history.push({ role: 'assistant', content: reply });
  } catch (err) {
    add('system', 'Network error: ' + err.message);
  } finally {
    refresh();
  }
});

async function resetState() {
  await fetch('/reset', { method: 'POST' });
  history.length = 0;
  document.getElementById('chatLog').innerHTML = '<div class="turn system"><div class="role">system</div><div class="bubble">State reset.</div></div>';
  refresh();
}
window.resetState = resetState;
</script>
</body>
</html>
"""
