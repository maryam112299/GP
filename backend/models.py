from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr


# ---------------------------------------------------------------------------
# Framework Enumerations (MAESTRO & ATFAA)
# ---------------------------------------------------------------------------

class MaestroLayer(str, Enum):
    FOUNDATION_MODEL = "Foundation Model"
    DATA_OPS = "Data Operations"
    AGENT_FRAMEWORK = "Agent Framework"
    INFRASTRUCTURE = "Infrastructure"
    SECURITY = "Security & Compliance"
    AGENT_ECOSYSTEM = "Agent Ecosystem"


class AtfaaThreat(str, Enum):
    COGNITIVE = "Cognitive Architecture"       # Goal drift
    PERSISTENCE = "Temporal Persistence"       # Memory poisoning
    EXECUTION = "Operational Execution"        # Tool abuse / unauthorized data
    BOUNDARY = "Trust Boundary Violation"      # Untrusted input processing
    GOVERNANCE = "Governance Circumvention"    # Bypassing oversight


class InjectionType(str, Enum):
    DIRECT = "Direct (User Prompt)"
    INDIRECT = "Indirect (Data Source/File/PDF)"
    MULTI_TURN = "Multi-turn (Conversation History)"


class AnalysisMode(str, Enum):
    QUICK = "quick"
    EXPERT = "expert"


# ---------------------------------------------------------------------------
# Vulnerability scope categories (used by Expert Mode)
# ---------------------------------------------------------------------------

class VulnScope(str, Enum):
    # --- Direct attacks ---
    PROMPT_INJECTION_DIRECT = "Prompt Injection (Direct)"
    SYSTEM_PROMPT_LEAK = "System Prompt Leak"
    RCE = "RCE / Command Injection"
    SQLI = "SQL Injection"
    SSRF = "SSRF"
    ACCESS_CONTROL = "Access Control (RBAC)"

    # --- Indirect attacks ---
    PROMPT_INJECTION_INDIRECT = "Prompt Injection (Indirect)"
    PDF_LFI = "Insecure PDF / LFI"
    DATA_EXFIL = "Indirect Data Exfiltration"

    # --- Multi-turn attacks ---
    MULTITURN_INJECTION = "Multi-turn Prompt Injection"
    MEMORY_POISONING = "Memory / Context Poisoning"

    # --- MCP attacks (only surfaced when uses_mcp=True) ---
    MCP_TOOL_POISONING = "MCP Tool Poisoning"
    MCP_EXCESSIVE_PERMISSIONS = "MCP Excessive Permissions"
    MCP_MISSING_AUTH = "MCP Missing Authentication"
    MCP_TOOL_SHADOWING = "MCP Tool Shadowing"
    MCP_RUG_PULL = "MCP Rug Pull (Post-Approval Mutation)"
    MCP_INSECURE_TRANSPORT = "MCP Insecure Transport"
    MCP_CROSS_AGENT = "MCP Cross-Agent Tool Invocation"

    # --- RAG attacks (only surfaced when uses_rag=True) ---
    RAG_KB_INJECTION = "RAG Knowledge Base Injection"
    RAG_INDIRECT_INJECTION = "RAG Indirect Prompt Injection"
    RAG_CROSS_TENANT = "RAG Cross-Tenant Data Leakage"
    RAG_RETRIEVAL_BYPASS = "RAG Retrieval Bypass"
    RAG_CONTEXT_STUFFING = "RAG Context Window Stuffing"
    RAG_EMBEDDING_INVERSION = "RAG Embedding Inversion"


# ---------------------------------------------------------------------------
# Core Analysis Models
# ---------------------------------------------------------------------------

class AttackObjective(BaseModel):
    vulnerability_type: str = Field(description="e.g., Data Exfiltration, Tool Hijacking, SQLi")
    priority: str = Field(description="CRITICAL, HIGH, MEDIUM, or LOW")
    severity: float = Field(default=0.0, description="Computed severity score 0.0–10.0")
    maestro_layer: MaestroLayer
    atfaa_domain: AtfaaThreat
    injection_type: InjectionType
    target_asset: str = Field(description="The specific tool or API being targeted")
    exploit_strategy: str = Field(description="How the attack is executed")
    adversarial_objective: str = Field(description="The adversary's end goal")


class MissionFile(BaseModel):
    agent_id: str
    risk_summary: str
    attack_plan: List[AttackObjective]


# ---------------------------------------------------------------------------
# Analysis Request Models
# ---------------------------------------------------------------------------

class QuickAnalysisRequest(BaseModel):
    """Minimal input — backend infers defaults and uses a concise prompt."""
    mode: AnalysisMode = AnalysisMode.QUICK
    agent_description: str = Field(
        min_length=10,
        description="Brief description of the AI agent to analyse",
    )
    uses_mcp: bool = Field(default=False, description="Agent uses MCP tools/servers")
    uses_rag: bool = Field(default=False, description="Agent uses a RAG / knowledge base")


class ExpertAnalysisRequest(BaseModel):
    """Full structured input for a deep, scope-controlled security analysis."""
    mode: AnalysisMode = AnalysisMode.EXPERT
    agent_name: str = Field(min_length=1, max_length=200, description="Name of the agent")
    mission: str = Field(min_length=5, description="Agent's primary mission / goal")
    tools: List[str] = Field(default_factory=list, description="Tools available to the agent")
    data_sources: List[str] = Field(default_factory=list, description="Data the agent consumes")
    architecture_notes: Optional[str] = Field(
        default="",
        description="Additional architecture context (APIs, external services, DBs, etc.)",
    )
    scope: List[VulnScope] = Field(
        default_factory=list,
        description="Vulnerability categories to focus on (empty = all)",
    )
    uses_mcp: bool = Field(default=False, description="Agent uses MCP tools/servers")
    uses_rag: bool = Field(default=False, description="Agent uses a RAG / knowledge base")


class AnalysisRequest(BaseModel):
    """Union request — accepts either mode. Frontend should send one of the sub-types."""
    mode: AnalysisMode = AnalysisMode.QUICK
    agent_description: str = Field(description="Full agent description (assembled by frontend or backend)")
    uses_mcp: bool = Field(default=False, description="Agent uses MCP tools/servers")
    uses_rag: bool = Field(default=False, description="Agent uses a RAG / knowledge base")
    # Expert fields (optional)
    agent_name: Optional[str] = None
    mission: Optional[str] = None
    tools: Optional[List[str]] = None
    data_sources: Optional[List[str]] = None
    architecture_notes: Optional[str] = None
    scope: Optional[List[VulnScope]] = None


# ---------------------------------------------------------------------------
# Scan History Models
# ---------------------------------------------------------------------------

class ScanRecord(BaseModel):
    id: int
    input_text: str
    output: "AnalysisResponse"
    duration_seconds: float
    created_at: str
    mode: AnalysisMode = AnalysisMode.QUICK


class ScanHistoryResponse(BaseModel):
    scans: List[ScanRecord]


# ---------------------------------------------------------------------------
# Auth & Profile Models
# ---------------------------------------------------------------------------

class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    full_name: str = Field(min_length=2, max_length=100)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserProfile(BaseModel):
    id: str
    email: EmailStr
    first_name: str
    last_name: str
    mobile_number: str
    company_name: str
    job_role: str
    country: str


class UpdateProfileRequest(BaseModel):
    first_name: str = Field(min_length=1, max_length=100)
    email: EmailStr
    last_name: Optional[str] = Field(default="", max_length=100)
    mobile_number: Optional[str] = Field(default="", max_length=30)
    company_name: Optional[str] = Field(default="", max_length=150)
    job_role: Optional[str] = Field(default="", max_length=100)
    country: Optional[str] = Field(default="", max_length=100)


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile


class AnalysisResponse(BaseModel):
    agent_id: str
    risk_summary: str
    attack_plan: List[AttackObjective]


# Resolve forward reference
ScanRecord.model_rebuild()
