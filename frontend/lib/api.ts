/**
 * api.ts — Centralised API client.
 *
 * All network calls go through this module so that:
 * - The base URL is in one place
 * - Auth header injection is handled once
 * - Error normalisation is consistent
 *
 * Auth strategy (#10):
 *   - Login/signup → backend sets an httpOnly cookie automatically
 *   - Every request uses `credentials: 'include'` so the cookie is sent
 *   - The Bearer token returned in the JSON body is kept as a fallback
 *     for clients that cannot use cookies (e.g., native apps / curl)
 *
 * 401 handling (#2):
 *   - `handleResponse` throws 'SESSION_EXPIRED' on any 401 so every
 *     endpoint (not just /api/analyze) can trigger a clean logout.
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

/** Headers for JSON requests that DO NOT need auth (cookie is sent automatically). */
function jsonHeaders() {
  return { 'Content-Type': 'application/json' } as const;
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

/**
 * Shared response handler (#2 fix):
 * - Throws 'SESSION_EXPIRED' on ANY 401 (not just /api/analyze)
 * - Normalises all other errors through parseErrorMessage
 */
async function handleResponse<T>(res: Response): Promise<T> {
  const data = await res.json().catch(() => null);
  if (res.status === 401) {
    throw new Error('SESSION_EXPIRED');
  }
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
      headers: jsonHeaders(),
      credentials: 'include',          // receive httpOnly cookie (#10)
      body: JSON.stringify({ email, password }),
    });
    return handleResponse<AuthResponse>(res);
  },

  async signup(fullName: string, email: string, password: string): Promise<AuthResponse> {
    const res = await fetch(`${API_BASE}/api/auth/signup`, {
      method: 'POST',
      headers: jsonHeaders(),
      credentials: 'include',          // receive httpOnly cookie (#10)
      body: JSON.stringify({ full_name: fullName, email, password }),
    });
    return handleResponse<AuthResponse>(res);
  },

  async me(token?: string): Promise<UserProfile> {
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${API_BASE}/api/auth/me`, {
      headers,
      credentials: 'include',
    });
    return handleResponse<UserProfile>(res);
  },

  async logout(): Promise<void> {
    await fetch(`${API_BASE}/api/auth/logout`, {
      method: 'POST',
      credentials: 'include',
    });
  },
};

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

export const profileApi = {
  async get(token?: string): Promise<UserProfile> {
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${API_BASE}/api/profile`, {
      headers,
      credentials: 'include',
    });
    return handleResponse<UserProfile>(res);
  },

  async update(token: string, data: Partial<UserProfile>): Promise<UserProfile> {
    const res = await fetch(`${API_BASE}/api/profile`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      credentials: 'include',
      body: JSON.stringify(data),
    });
    return handleResponse<UserProfile>(res);
  },
};

// ---------------------------------------------------------------------------
// Scans
// ---------------------------------------------------------------------------

export const scansApi = {
  async getAll(token?: string): Promise<ScanHistoryResponse> {
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const res = await fetch(`${API_BASE}/api/scans`, {
      headers,
      credentials: 'include',
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
  uses_mcp: boolean;
  uses_rag: boolean;
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
  uses_mcp: boolean;
  uses_rag: boolean;
}

export type AnalysisPayload = QuickAnalysisPayload | ExpertAnalysisPayload;

export const analysisApi = {
  async analyze(token: string, payload: AnalysisPayload): Promise<MissionFile> {
    const res = await fetch(`${API_BASE}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      credentials: 'include',   // send httpOnly cookie (#10)
      body: JSON.stringify(payload),
    });
    // handleResponse already handles 401 → SESSION_EXPIRED (#2)
    return handleResponse<MissionFile>(res);
  },

  buildQuickPayload(
    description: string,
    uses_mcp: boolean,
    uses_rag: boolean,
  ): QuickAnalysisPayload {
    return { mode: 'quick', agent_description: description, uses_mcp, uses_rag };
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
      uses_mcp: config.uses_mcp,
      uses_rag: config.uses_rag,
    };
  },
};
