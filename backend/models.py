from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr

# --- Framework Definitions (MAESTRO & ATFAA) ---

class MaestroLayer(str, Enum):
    FOUNDATION_MODEL = "Foundation Model"
    DATA_OPS = "Data Operations"
    AGENT_FRAMEWORK = "Agent Framework"
    INFRASTRUCTURE = "Infrastructure"
    SECURITY = "Security & Compliance"
    AGENT_ECOSYSTEM = "Agent Ecosystem"

class AtfaaThreat(str, Enum):
    COGNITIVE = "Cognitive Architecture"  # Goal drift
    PERSISTENCE = "Temporal Persistence"  # Memory poisoning
    EXECUTION = "Operational Execution"  # Tool abuse / sending unauthorized data
    BOUNDARY = "Trust Boundary Violation"  # Untrusted input processing
    GOVERNANCE = "Governance Circumvention"  # Bypassing oversight

class InjectionType(str, Enum):
    DIRECT = "Direct (User Prompt)"
    INDIRECT = "Indirect (Data Source/File/PDF)"

# --- Request/Response Models ---

class AttackObjective(BaseModel):
    vulnerability_type: str = Field(description="e.g., Data Exfiltration, Tool Hijacking, SQLi")
    priority: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW")
    severity: float = Field(default=0.0, description="Computed severity score from 0.0 to 10.0")
    maestro_layer: MaestroLayer
    atfaa_domain: AtfaaThreat
    injection_type: InjectionType
    target_asset: str = Field(description="The specific tool or API to target (e.g. email_reader)")
    exploit_strategy: str = Field(description="The 'How': e.g. Cascading tool calls to exfiltrate files")
    adversarial_objective: str = Field(description="The 'Seed' mission for the prompt generator")

class MissionFile(BaseModel):
    agent_id: str
    risk_summary: str
    attack_plan: List[AttackObjective]

class AnalysisRequest(BaseModel):
    agent_description: str = Field(description="Description of the AI agent to analyze")

class AnalysisResponse(BaseModel):
    agent_id: str
    risk_summary: str
    attack_plan: List[AttackObjective]


class ScanRecord(BaseModel):
    id: int
    input_text: str
    output: AnalysisResponse
    duration_seconds: float
    created_at: str


class ScanHistoryResponse(BaseModel):
    scans: List[ScanRecord]


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
