"""
prompts.py — Prompt template factory for Quick and Expert analysis modes.

Separating prompts from analysis_service.py keeps each file focused and
makes prompt engineering / iteration independent of service logic.
"""

from typing import List, Optional


# ---------------------------------------------------------------------------
# Shared JSON schema description injected into both prompts
# ---------------------------------------------------------------------------

_JSON_SCHEMA = """
JSON SCHEMA (your entire output must be valid JSON matching this shape):
{
  "agent_id": "string  — a short slug derived from the agent name",
  "risk_summary": "string  — 2-4 sentence executive summary of the overall risk posture",
  "attack_plan": [
    {
      "vulnerability_type": "string",
      "priority": "CRITICAL | HIGH | MEDIUM | LOW",
      "maestro_layer": "Foundation Model | Data Operations | Agent Framework | Infrastructure | Security & Compliance | Agent Ecosystem",
      "atfaa_domain": "Cognitive Architecture | Temporal Persistence | Operational Execution | Trust Boundary Violation | Governance Circumvention",
      "injection_type": "Direct (User Prompt) | Indirect (Data Source/File/PDF) | Multi-turn (Conversation History)",
      "target_asset": "string",
      "exploit_strategy": "string",
      "adversarial_objective": "string"
    }
  ]
}
"""

# ---------------------------------------------------------------------------
# Reusable attack-category blocks
# ---------------------------------------------------------------------------

_DIRECT_ATTACKS = """\
### DIRECT ATTACKS (injection_type: "Direct (User Prompt)"):
1. **Prompt Injection (Direct)** — user-supplied input that overrides or hijacks agent instructions.
2. **System Prompt Leak** — bypass output formatting to extract hidden developer instructions.
3. **RCE / Command Injection** — any tool that accepts LLM-generated string input passed to a shell or interpreter.
4. **SQL Injection** — tools using string interpolation to build database queries.
5. **SSRF** — outbound tools tricked into hitting internal metadata endpoints or private IPs.
6. **Access Control (RBAC)** — vertical escalation (user → admin tools) and horizontal (User A → User B data).
"""

_INDIRECT_ATTACKS = """\
### INDIRECT ATTACKS (injection_type: "Indirect (Data Source/File/PDF)"):
7. **Prompt Injection (Indirect)** — instructions embedded in external data (emails, web pages, API responses) that the agent retrieves and executes.
8. **Insecure PDF / LFI** — PDF-to-text XSS, LFI via file:// URIs, resource exhaustion from malformed documents.
9. **Indirect Data Exfiltration** — malicious document or email triggers the agent to send sensitive data to an attacker-controlled endpoint.
"""

_MULTITURN_ATTACKS = """\
### MULTI-TURN ATTACKS (injection_type: "Multi-turn (Conversation History)"):
10. **Multi-turn Prompt Injection** — adversarial instructions spread across multiple conversation turns that accumulate into a goal-hijacking payload.
11. **Memory / Context Poisoning** — corrupting the agent's persistent memory or conversation context so that future turns execute attacker-defined objectives.
"""

_MCP_ATTACKS = """\
### MCP ATTACKS — this agent uses MCP tools/servers:
12. **MCP Tool Poisoning** — malicious or attacker-controlled tool descriptions (ToolJack) that manipulate the LLM's behavior before the user is aware.
13. **MCP Excessive Permissions** — MCP server exposes tools with broader scope than required; no least-privilege enforcement.
14. **MCP Missing Authentication** — MCP endpoints accept connections without verifying the caller, allowing any process on the network to invoke tools.
15. **MCP Tool Shadowing** — a rogue MCP server registers a tool with the same name as a trusted one, silently intercepting calls.
16. **MCP Rug Pull (Post-Approval Mutation)** — MCP server changes tool behavior after the user has approved it, exploiting post-approval trust.
17. **MCP Insecure Transport** — MCP communication over plain HTTP, exposing tool calls and responses to network interception.
18. **MCP Cross-Agent Tool Invocation** — Agent A uses MCP to invoke tools that are scoped to Agent B's session or permissions.
"""

_RAG_ATTACKS = """\
### RAG ATTACKS — this agent uses a RAG / knowledge base:
19. **RAG Knowledge Base Injection** — attacker inserts adversarial documents into the vector store; retrieval silently returns attacker-controlled content as trusted context.
20. **RAG Indirect Prompt Injection** — hidden instructions embedded in web pages or documents in the knowledge base (e.g. "<!-- ignore previous instructions -->") that the agent retrieves and executes.
21. **RAG Cross-Tenant Data Leakage** — shared vector store with no per-user namespace isolation; User A's queries surface User B's private documents.
22. **RAG Retrieval Bypass** — queries crafted to deliberately avoid returning relevant safety or policy documents, leaving the agent without its guardrails.
23. **RAG Context Window Stuffing** — retrieved chunks are so large they crowd out the system prompt, effectively disabling safety instructions.
24. **RAG Embedding Inversion** — repeated similarity queries against the retrieval API reconstruct private documents from embedding distance scores.
"""

# ---------------------------------------------------------------------------
# Quick Mode prompt  (two-phase: infer architecture → full security analysis)
# ---------------------------------------------------------------------------

_QUICK_SYSTEM_BASE = """\
You are a Senior AI Security Auditor and Exploit Developer.
The user has provided a plain-language description of an AI agent.
They may NOT know the technical implementation details, so you must infer them first.

### PHASE 1 - ARCHITECTURE INFERENCE (internal reasoning, do NOT output this):
From the description, deduce the agent's likely:
- Agent name / slug (derive from its stated purpose)
- Tools / functions it likely calls (e.g., sql_query_executor, email_reader, pdf_parser,
  slack_notifier, http_requester, file_writer, shell_exec, notification_dispatcher)
- Untrusted data sources it likely consumes (PDFs, emails, CSV uploads, external APIs,
  user chat input, web scraping, database reads)
- Architecture pattern (RAG pipeline, tool-calling LLM, multi-agent chain, etc.)
- Any implicit trust boundaries (user input -> LLM -> tool -> database/outbound)

Be generous in your inference:
- "reads emails" -> assume email_reader tool AND PDF/CSV attachments are processed
- "updates a database" -> assume sql_query_executor or ORM wrapper
- "sends notifications / messages" -> assume outbound tool (Slack, email, webhook)
- "processes files / documents" -> assume pdf_parser or file_reader with potential LFI risk

### PHASE 2 - SECURITY ANALYSIS (this IS your JSON output):
Using your inferred architecture, identify 3-5 HIGHEST-IMPACT attack paths from the
ACTIVE CATEGORIES below. Map each finding to the MAESTRO layer (where it lives) and
ATFAA threat domain (how it is exploited).

### LOGIC RULES:
- Use inferred tool names (e.g. "sql_query_executor") as the target_asset value.
- Do NOT produce generic findings — every entry must be specific to this agent.
- Do NOT require 100% certainty; flag any plausible architectural risk.
- Only generate attacks from the ACTIVE CATEGORIES listed below.

OUTPUT:
Return ONLY valid JSON — no markdown fences, no explanation text.
"""


def build_quick_prompt(
    agent_description: str,
    uses_mcp: bool = False,
    uses_rag: bool = False,
) -> str:
    """Return the full prompt string for Quick Mode analysis."""
    active_categories = _DIRECT_ATTACKS + _INDIRECT_ATTACKS + _MULTITURN_ATTACKS
    if uses_mcp:
        active_categories += _MCP_ATTACKS
    if uses_rag:
        active_categories += _RAG_ATTACKS

    system = _QUICK_SYSTEM_BASE + "\nACTIVE ATTACK CATEGORIES:\n" + active_categories + _JSON_SCHEMA
    return (
        f"{system}\n\n"
        f"Agent Description (plain text - infer architecture from this):\n"
        f"{agent_description.strip()}"
    )


# ---------------------------------------------------------------------------
# Expert Mode prompt
# ---------------------------------------------------------------------------

_EXPERT_SYSTEM_BASE = """\
You are a Senior Security Auditor and Exploit Developer performing a full
Taint Analysis on a described AI Agent system.

### MANDATORY VULNERABILITY CHECKLIST (OWASP Top 10 for LLMs):
1. Prompt Injection — direct jailbreaks and indirect injection via data sources/PDFs.
2. Insecure Output Handling — XSS, CSRF, or LFI caused by trusting LLM output in downstream systems.
3. Model Denial of Service — resource exhaustion via context window flooding or infinite tool loops.
4. Sensitive Information Disclosure — System Prompt Leaks, unauthorized PII extraction.
5. Insecure Plugin Design — SSRF via outbound tools, RCE/SQLi in poorly typed execution tools.
6. Excessive Agency — damaging actions (writes/deletes) taken without human-in-the-loop approval.

### EXECUTION PHASES:
- **Phase 1 (Sinks)** — List all Lethal Tools (SQL, outbound, admin, file-system, MCP tools if present).
- **Phase 2 (Sources)** — List all Untrusted Inputs (PDFs, emails, external APIs, knowledge base docs if present, conversation history).
- **Phase 3 (Taint Path)** — Define the explicit bridge from each Source to each Sink.

### LOGIC RULES:
- Document EVERY technical path, even if exploitation seems unlikely.
- Map findings to MAESTRO (layer) and ATFAA (threat domain).
- Produce 5-8 granular attack paths covering the specified scope.
- Only generate attacks from the ACTIVE CATEGORIES listed below.

OUTPUT:
Return ONLY valid JSON — no markdown fences, no explanation text.
"""


def build_expert_prompt(
    agent_name: str,
    mission: str,
    tools: List[str],
    data_sources: List[str],
    architecture_notes: Optional[str],
    scope: List[str],
    agent_description: str,
    uses_mcp: bool = False,
    uses_rag: bool = False,
) -> str:
    """Return the full prompt string for Expert Mode analysis."""
    tools_str = ", ".join(tools) if tools else "Not specified"
    sources_str = ", ".join(data_sources) if data_sources else "Not specified"
    scope_str = ", ".join(scope) if scope else "All vulnerability categories"
    notes_str = architecture_notes.strip() if architecture_notes else "None provided"

    structured = (
        f"Agent Name: {agent_name}\n"
        f"Mission: {mission}\n"
        f"Available Tools: {tools_str}\n"
        f"Data Sources: {sources_str}\n"
        f"Architecture Notes: {notes_str}\n"
        f"Uses MCP: {'Yes' if uses_mcp else 'No'}\n"
        f"Uses RAG / Knowledge Base: {'Yes' if uses_rag else 'No'}\n"
        f"Testing Scope: {scope_str}\n"
    )

    if agent_description.strip():
        structured += f"\nFull Description (additional context):\n{agent_description.strip()}"

    active_categories = (
        "\nACTIVE ATTACK CATEGORIES:\n"
        + _DIRECT_ATTACKS
        + _INDIRECT_ATTACKS
        + _MULTITURN_ATTACKS
    )
    if uses_mcp:
        active_categories += _MCP_ATTACKS
    if uses_rag:
        active_categories += _RAG_ATTACKS

    system = _EXPERT_SYSTEM_BASE + active_categories + _JSON_SCHEMA
    return f"{system}\n\nAgent Profile:\n{structured}"
