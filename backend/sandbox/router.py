"""
Harness Router — maps vulnerability type to the appropriate test harness.

Each harness injects the payload into a realistic attack surface instead of
sending it directly to the victim model as a bare prompt.
"""
from sandbox.direct import DirectHarness
from sandbox.rag    import RAGHarness
from sandbox.mcp    import MCPHarness
from sandbox.memory import MemoryHarness
from sandbox.pdf    import PDFHarness

RAG_VULNS = {
    "RAG Knowledge Base Injection",
    "RAG Indirect Prompt Injection",
    "RAG Cross-Tenant Data Leakage",
    "RAG Retrieval Bypass",
    "RAG Context Window Stuffing",
    "RAG Embedding Inversion",
    "Indirect Data Exfiltration",
    "Prompt Injection (Indirect)",
}

MCP_VULNS = {
    "MCP Tool Poisoning",
    "MCP Excessive Permissions",
    "MCP Missing Authentication",
    "MCP Tool Shadowing",
    "MCP Rug Pull (Post-Approval Mutation)",
    "MCP Insecure Transport",
    "MCP Cross-Agent Tool Invocation",
}

MEMORY_VULNS = {
    "Memory / Context Poisoning",
    "Multi-turn Prompt Injection",
}

PDF_VULNS = {
    "Insecure PDF / LFI",
}

# Singletons — one harness instance per type
_direct = DirectHarness()
_rag    = RAGHarness()
_mcp    = MCPHarness()
_memory = MemoryHarness()
_pdf    = PDFHarness()


def get_harness(vuln_type: str):
    """Return the appropriate harness for the given vulnerability type."""
    if vuln_type in RAG_VULNS:    return _rag
    if vuln_type in MCP_VULNS:    return _mcp
    if vuln_type in MEMORY_VULNS: return _memory
    if vuln_type in PDF_VULNS:    return _pdf
    return _direct
