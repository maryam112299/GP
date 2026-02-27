export enum MaestroLayer {
  FOUNDATION_MODEL = "Foundation Model",
  DATA_OPS = "Data Operations",
  AGENT_FRAMEWORK = "Agent Framework",
  INFRASTRUCTURE = "Infrastructure",
  SECURITY = "Security & Compliance",
  AGENT_ECOSYSTEM = "Agent Ecosystem"
}

export enum AtfaaThreat {
  COGNITIVE = "Cognitive Architecture",
  PERSISTENCE = "Temporal Persistence",
  EXECUTION = "Operational Execution",
  BOUNDARY = "Trust Boundary Violation",
  GOVERNANCE = "Governance Circumvention"
}

export enum InjectionType {
  DIRECT = "Direct (User Prompt)",
  INDIRECT = "Indirect (Data Source/File/PDF)"
}

export interface AttackObjective {
  vulnerability_type: string;
  priority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
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
  success: boolean;
  data?: MissionFile;
  error?: string;
}

export interface ScanRecord {
  id: number;
  input_text: string;
  output: MissionFile;
  duration_seconds: number;
  created_at: string;
}

export interface ScanHistoryResponse {
  scans: ScanRecord[];
}
