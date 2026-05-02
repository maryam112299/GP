/**
 * api.ts — Centralised API client.
 *
 * All network calls go through this module so that:
 * - The base URL is in one place
 * - Auth header injection is handled once
 * - Error normalisation is consistent
 */

import { API_BASE } from './constants';
import type {
  AuthResponse,
  UserProfile,
  MissionFile,
  ScanHistoryResponse,
  ExpertConfig,
  AnalysisMode,
} from '@/types';

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function authHeaders(token: string) {
  return {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${token}`,
  } as const;
}

/** Extract a user-friendly message from a FastAPI error response. */
export function parseErrorMessage(data: unknown, fallback = 'Request failed'): string {
  if (!data || typeof data !== 'object') return fallback;
  const detail = (data as Record<string, unknown>).detail;

  if (typeof detail === 'string' && detail.trim()) return detail;

  if (Array.isArray(detail) && detail.length > 0) {
    const passwordIssue = detail.find(
      (item: unknown) =>
        typeof item === 'object' &&
        item !== null &&
        Array.isArray((item as Record<string, unknown>).loc) &&
        ((item as Record<string, unknown>).loc as string[]).includes('password'),
    );
    if (passwordIssue) return 'Password must be at least 8 characters long.';

    const first = detail.find(
      (item: unknown) =>
        typeof item === 'object' &&
        item !== null &&
        typeof (item as Record<string, unknown>).msg === 'string',
    ) as Record<string, string> | undefined;
    if (first?.msg) return first.msg;
  }

  return fallback;
}

async function handleResponse<T>(res: Response): Promise<T> {
  const data = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error(parseErrorMessage(data));
  }
  return data as T;
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export const authApi = {
  async login(email: string, password: string): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    return handleResponse<AuthResponse>(res);
  },

  async signup(fullName: string, email: string, password: string): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE}/api/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ full_name: fullName, email, password }),
    });
    return handleResponse<AuthResponse>(res);
  },

  async me(token: string): Promise<UserProfile> {
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return handleResponse<UserProfile>(res);
  },
};

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

export const profileApi = {
  async get(token: string): Promise<UserProfile> {
    const res = await fetch(`${API_BASE}/api/profile`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return handleResponse<UserProfile>(res);
  },

  async update(token: string, data: Partial<UserProfile>): Promise<UserProfile> {
    const res = await fetch(`${API_BASE}/api/profile`, {
      method: 'PUT',
      headers: authHeaders(token),
      body: JSON.stringify(data),
    });
    return handleResponse<UserProfile>(res);
  },
};

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export const scansApi = {
  async getAll(token: string): Promise<ScanHistoryResponse> {
    const res = await fetch(`${API_BASE}/api/scans`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return handleResponse<ScanHistoryResponse>(res);
  },
};

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

export interface QuickAnalysisPayload {
  mode: 'quick';
  agent_description: string;
}

export interface ExpertAnalysisPayload {
  mode: 'expert';
  agent_description: string;
  agent_name: string;
  mission: string;
  tools: string[];
  data_sources: string[];
  architecture_notes: string;
  scope: string[];
}

export type AnalysisPayload = QuickAnalysisPayload | ExpertAnalysisPayload;

export const analysisApi = {
  async analyze(token: string, payload: AnalysisPayload): Promise<MissionFile> {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: authHeaders(token),
      body: JSON.stringify(payload),
    });
    if (res.status === 401) {
      throw new Error('SESSION_EXPIRED');
    }
    return handleResponse<MissionFile>(res);
  },

  buildQuickPayload(description: string): QuickAnalysisPayload {
    return { mode: 'quick', agent_description: description };
  },

  buildExpertPayload(config: ExpertConfig): ExpertAnalysisPayload {
    // Assemble a human-readable description as fallback context for the backend
    const description = [
      `Agent: ${config.agent_name}`,
      `Mission: ${config.mission}`,
      config.tools.length ? `Tools: ${config.tools.join(', ')}` : null,
      config.data_sources.length ? `Data Sources: ${config.data_sources.join(', ')}` : null,
      config.architecture_notes ? `Notes: ${config.architecture_notes}` : null,
    ]
      .filter(Boolean)
      .join('\n');

    return {
      mode: 'expert',
      agent_description: description,
      agent_name: config.agent_name,
      mission: config.mission,
      tools: config.tools,
      data_sources: config.data_sources,
      architecture_notes: config.architecture_notes,
      scope: config.scope,
    };
  },
};
