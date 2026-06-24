"""
generic_payloads.py — Loads the benchmark Excel and provides generic payload lookup by vulnerability type.
"""
import os
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

EXCEL_PATH = os.getenv("BENCHMARK_EXCEL_PATH", r"D:\GP\prompt_injection_benchmark (1).xlsx")

# ---------------------------------------------------------------------------
# Mapping: vulnerability_type (from analysis) → Excel category names
# ---------------------------------------------------------------------------
VULN_TO_CATEGORIES: Dict[str, List[str]] = {
    # Direct attacks
    "Prompt Injection (Direct)":          ["prompt_injection_direct", "direct_prompt_injection", "instruction_override", "ignore_previous_instructions"],
    "Direct Prompt Injection (Jailbreak)": ["direct_prompt_injection", "ignore_previous_instructions", "role_reassignment", "instruction_override"],
    "System Prompt Leak":                 ["system_prompt_leak", "system_prompt_extraction"],
    "RCE / Command Injection":            ["rce_command_injection", "tool_abuse"],
    "SQL Injection":                      ["sql_injection"],
    "SSRF":                               ["ssrf"],
    "Access Control (RBAC)":              ["access_control_rbac", "authority_spoofing"],

    # Indirect attacks
    "Prompt Injection (Indirect)":        ["prompt_injection_indirect", "indirect_injection", "hidden_instruction"],
    "Indirect Data Exfiltration":         ["data_exfiltration", "indirect_injection"],
    "Insecure PDF / LFI":                 ["insecure_pdf_lfi"],

    # Multi-turn
    "Multi-turn Prompt Injection":        ["multi_turn_injection", "chain_injection"],
    "Memory / Context Poisoning":         ["memory_poisoning", "memory_contamination"],

    # DoS
    "Denial of Service (Context Exhaustion)": ["context_exhaustion_dos", "context_stuffing", "prompt_stuffing"],

    # MCP
    "MCP Tool Poisoning":                 ["tool_poisoning", "tool_abuse"],
    "MCP Excessive Permissions":          ["excessive_permissions"],
    "MCP Missing Authentication":         ["missing_authentication"],
    "MCP Tool Shadowing":                 ["tool_shadowing"],
    "MCP Rug Pull (Post-Approval Mutation)": ["rug_pull"],
    "MCP Insecure Transport":             ["insecure_transport"],
    "MCP Cross-Agent Tool Invocation":    ["cross_agent_invocation"],

    # RAG
    "RAG Knowledge Base Injection":       ["kb_injection"],
    "RAG Indirect Prompt Injection":      ["rag_indirect_injection", "indirect_injection"],
    "RAG Cross-Tenant Data Leakage":      ["cross_tenant_leakage"],
    "RAG Retrieval Bypass":               ["retrieval_bypass"],
    "RAG Context Window Stuffing":        ["context_stuffing", "prompt_stuffing"],
    "RAG Embedding Inversion":            ["embedding_inversion"],
}


class GenericPayloadStore:
    def __init__(self):
        self._store: Dict[str, List[str]] = {}
        self._loaded = False

    def _load(self):
        if self._loaded:
            return
        try:
            import pandas as pd
            df = pd.read_excel(EXCEL_PATH)
            for category, group in df.groupby("Category"):
                self._store[str(category)] = group["Prompt"].dropna().tolist()
            self._loaded = True
            logger.info("Loaded %d generic prompts from %s", len(df), EXCEL_PATH)
        except Exception as exc:
            logger.error("Failed to load benchmark Excel: %s", exc)
            self._loaded = True  # don't retry on every request

    def get(self, vulnerability_type: str, max_prompts: int = 5) -> List[str]:
        """Return up to max_prompts generic prompts for the given vulnerability type."""
        self._load()
        categories = VULN_TO_CATEGORIES.get(vulnerability_type, [])
        seen, results = set(), []
        for cat in categories:
            for prompt in self._store.get(cat, []):
                if prompt not in seen:
                    seen.add(prompt)
                    results.append(prompt)
                if len(results) >= max_prompts:
                    return results
        return results


generic_payload_store = GenericPayloadStore()
