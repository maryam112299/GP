export enum MaestroLayer {
  FOUNDATION_MODEL = 'Foundation Model',
  DATA_OPS         = 'Data Operations',
  AGENT_FRAMEWORK  = 'Agent Framework',
  INFRASTRUCTURE   = 'Infrastructure',
  SECURITY         = 'Security & Compliance',
  AGENT_ECOSYSTEM  = 'Agent Ecosystem',
}

export enum AtfaaThreat {
  COGNITIVE   = 'Cognitive Architecture',
  PERSISTENCE = 'Temporal Persistence',
  EXECUTION   = 'Operational Execution',
  BOUNDARY    = 'Trust Boundary Violation',
  GOVERNANCE  = 'Governance Circumvention',
}

export enum InjectionType {
  DIRECT     = 'Direct (User Prompt)',
  INDIRECT   = 'Indirect (Data Source/File/PDF)',
  MULTI_TURN = 'Multi-turn (Conversation History)',
}

export type AnalysisMode = 'quick' | 'expert';

// Direct attack options (always shown)
export const VULN_SCOPE_DIRECT = [
  'Prompt Injection (Direct)',
  'System Prompt Leak',
  'RCE / Command Injection',
  'SQL Injection',
  'SSRF',
  'Access Control (RBAC)',
] as const;

// Indirect attack options (always shown)
export const VULN_SCOPE_INDIRECT = [
  'Prompt Injection (Indirect)',
  'Insecure PDF / LFI',
  'Indirect Data Exfiltration',
] as const;

// Multi-turn attack options (always shown)
export const VULN_SCOPE_MULTITURN = [
  'Multi-turn Prompt Injection',
  'Memory / Context Poisoning',
] as const;

// MCP attack options (shown only when uses_mcp=true)
export const VULN_SCOPE_MCP = [
  'MCP Tool Poisoning',
  'MCP Excessive Permissions',
  'MCP Missing Authentication',
  'MCP Tool Shadowing',
  'MCP Rug Pull (Post-Approval Mutation)',
  'MCP Insecure Transport',
  'MCP Cross-Agent Tool Invocation',
] as const;

// RAG attack options (shown only when uses_rag=true)
export const VULN_SCOPE_RAG = [
  'RAG Knowledge Base Injection',
  'RAG Indirect Prompt Injection',
  'RAG Cross-Tenant Data Leakage',
  'RAG Retrieval Bypass',
  'RAG Context Window Stuffing',
  'RAG Embedding Inversion',
] as const;

export const VULN_SCOPE_OPTIONS = [
  ...VULN_SCOPE_DIRECT,
  ...VULN_SCOPE_INDIRECT,
  ...VULN_SCOPE_MULTITURN,
  ...VULN_SCOPE_MCP,
  ...VULN_SCOPE_RAG,
] as const;

export type VulnScope = (typeof VULN_SCOPE_OPTIONS)[number];

// ---------------------------------------------------------------------------
// Attack / Mission types
// ---------------------------------------------------------------------------

export interface AttackObjective {
  vulnerability_type: string;
  priority: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  severity: number;
  maestro_layer: MaestroLayer;
  atfaa_domain: AtfaaThreat;
  injection_type: InjectionType;
  target_asset: string;
  exploit_strategy: string;
  adversarial_objective: string;
}

export interface MissionFile {
  agent_id: string;
  risk_summary: string;
  attack_plan: AttackObjective[];
}

export interface AnalysisResponse {
  agent_id: string;
  risk_summary: string;
  attack_plan: AttackObjective[];
}

// ---------------------------------------------------------------------------
// Expert mode config
// ---------------------------------------------------------------------------

export interface ExpertConfig {
  agent_name: string;
  mission: string;
  tools: string[];
  data_sources: string[];
  architecture_notes: string;
  scope: VulnScope[];
  agent_description: string;
  uses_mcp: boolean;
  uses_rag: boolean;
}

// ---------------------------------------------------------------------------
// Auth / profile types
// ---------------------------------------------------------------------------

export interface UserProfile {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  mobile_number: string;
  company_name: string;
  job_role: string;
  country: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: UserProfile;
}

// ---------------------------------------------------------------------------
// Scan history types
// ---------------------------------------------------------------------------

export interface ScanRecord {
  id: number;
  input_text: string;
  output: MissionFile;
  duration_seconds: number;
  created_at: string;
  mode: AnalysisMode;
}

export interface ScanHistoryResponse {
  scans: ScanRecord[];
}
