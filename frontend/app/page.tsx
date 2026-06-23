'use client';

import { useEffect, useState, useCallback } from 'react';
import { Loader2 } from 'lucide-react';
import { authApi, analysisApi, redTeamApi, scansApi, type RedTeamLoopResponse } from '@/lib/api';
import type { MissionFile, UserProfile, AnalysisMode, ExpertConfig, ScanRecord } from '@/types';
import AppShell, { type AppView } from '@/components/layout/AppShell';
import AuthModal from '@/components/auth/AuthModal';
import ModeSelector from '@/components/analysis/ModeSelector';
import QuickAnalysis, { type QuickScanConfig } from '@/components/analysis/QuickAnalysis';
import ExpertAnalysis from '@/components/analysis/ExpertAnalysis';
import AnalyzingPanel from '@/components/analysis/AnalyzingPanel';
import ResultsDisplay from '@/components/ResultsDisplay';
import Dashboard from '@/components/dashboard/Dashboard';
import Settings from '@/components/settings/Settings';
import toast from 'react-hot-toast';
import { Shield } from 'lucide-react';

// ---------------------------------------------------------------------------
// DEV: set to true to skip login and preview the UI immediately.
// Flip back to false before real use / deployment.
// ---------------------------------------------------------------------------
const DEV_BYPASS_AUTH = false;

const DEV_FAKE_USER: UserProfile = {
  id:             'dev',
  email:          'dev@preview.local',
  first_name:     'Dev',
  last_name:      'Preview',
  mobile_number:  '',
  company_name:   'Security Team',
  job_role:       'Security Engineer',
  country:        '',
};

// ---------------------------------------------------------------------------
// Workspace phase
// ---------------------------------------------------------------------------
type WorkspacePhase = 'input' | 'analyzing' | 'results';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function scanDate(iso: string): string {
  const d = new Date(iso);
  const today = new Date();
  const diffDays = Math.floor((today.getTime() - d.getTime()) / 86400000);
  if (diffDays === 0) return `Today, ${d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })}`;
  if (diffDays === 1) return 'Yesterday';
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short' });
}

function scoreFromScan(scan: ScanRecord): number {
  const plan = scan.output?.attack_plan ?? [];
  if (!plan.length) return 0;
  const crit = plan.filter(o => o.priority === 'CRITICAL').length;
  const high = plan.filter(o => o.priority === 'HIGH').length;
  return Math.min(99, crit * 20 + high * 8);
}

// ---------------------------------------------------------------------------
export default function Home() {
  // Auth
  const [token,         setToken]         = useState('');
  const [user,          setUser]          = useState<UserProfile | null>(null);
  const [isAuthLoading, setIsAuthLoading] = useState(true);

  // Shell
  const [view,          setView]          = useState<AppView>('workspace');
  const [sessions,      setSessions]      = useState<{ id: string; agent: string; date: string; score: number }[]>([]);
  const [activeSession, setActiveSession] = useState<string | null>(null);

  // Analysis
  const [analysisMode,  setAnalysisMode]  = useState<AnalysisMode>('quick');
  const [phase,         setPhase]         = useState<WorkspacePhase>('input');
  const [results,       setResults]       = useState<MissionFile | null>(null);
  const [resultMode,    setResultMode]    = useState<AnalysisMode>('quick');
  const [durationSeconds, setDurationSeconds] = useState<number | null>(null);
  const [submittedDesc, setSubmittedDesc] = useState('');
  const [lastConfig,    setLastConfig]    = useState<QuickScanConfig | null>(null);

  // Quick-mode victim wiring
  const [victimUrl,    setVictimUrl]    = useState('');
  const [victimModel,  setVictimModel]  = useState('');
  const [maxPayloads,  setMaxPayloads]  = useState(5);
  const [loopResult,   setLoopResult]   = useState<RedTeamLoopResponse | null>(null);

  // -------------------------------------------------------------------------
  // Session restore
  // -------------------------------------------------------------------------
  useEffect(() => {
    if (DEV_BYPASS_AUTH) {
      setUser(DEV_FAKE_USER);
      setIsAuthLoading(false);
      return;
    }
    const stored = localStorage.getItem('auth_token');
    authApi.me(stored ?? undefined)
      .then(profile => {
        setUser(profile);
        if (stored) setToken(stored);
      })
      .catch(() => { localStorage.removeItem('auth_token'); })
      .finally(() => setIsAuthLoading(false));
  }, []);

  // Load scan history whenever token changes
  const refreshSessions = useCallback((tok: string) => {
    if (!tok || DEV_BYPASS_AUTH) return;
    scansApi.getAll(tok).then(r => {
      setSessions(
        r.scans.map(s => ({
          id:    String(s.id),
          agent: s.output?.agent_id || 'Unknown Agent',
          date:  scanDate(s.created_at),
          score: scoreFromScan(s),
        }))
      );
    }).catch(() => {});
  }, []);

  useEffect(() => { refreshSessions(token); }, [token, refreshSessions]);

  // -------------------------------------------------------------------------
  // Auth handlers
  // -------------------------------------------------------------------------
  const handleAuthenticated = useCallback((tok: string, profile: UserProfile) => {
    setToken(tok);
    setUser(profile);
  }, []);

  const handleLogout = useCallback(async () => {
    if (DEV_BYPASS_AUTH) { toast('Auth bypass is ON — sign-out disabled.'); return; }
    try { await authApi.logout(); } catch { /* best-effort */ }
    localStorage.removeItem('auth_token');
    setToken('');
    setUser(null);
    setResults(null);
    setPhase('input');
    setSessions([]);
  }, []);

  // -------------------------------------------------------------------------
  // New scan / session open
  // -------------------------------------------------------------------------
  const handleNewScan = useCallback(() => {
    setPhase('input');
    setResults(null);
    setLoopResult(null);
    setActiveSession(null);
    setView('workspace');
  }, []);

  const handleOpenSession = useCallback(async (id: string) => {
    setActiveSession(id);
    setView('workspace');
    setPhase('analyzing');
    setResults(null);
    setLoopResult(null);
    try {
      const scan = await scansApi.getById(id, token || undefined);
      setResults(scan.output);
      setResultMode((scan.mode as AnalysisMode) ?? 'quick');
      setSubmittedDesc(scan.input_text ?? '');
      setDurationSeconds(scan.duration_seconds ?? null);
      setPhase('results');
    } catch {
      toast.error('Failed to load session.');
      setPhase('input');
    }
  }, [token]);

  // -------------------------------------------------------------------------
  // Analysis
  // -------------------------------------------------------------------------
  const runAnalysis = useCallback(async (
    payload: Parameters<typeof analysisApi.analyze>[1],
  ) => {
    if (DEV_BYPASS_AUTH) { toast('Auth bypass is ON — connect a real backend to run analysis.'); return; }
    if (!token) { toast.error('Please sign in first.'); return; }
    setPhase('analyzing');
    setResults(null);
    setDurationSeconds(null);
    const t0 = performance.now();
    try {
      const data = await analysisApi.analyze(token, payload);
      setResults(data);
      setResultMode(payload.mode as AnalysisMode);
      setSubmittedDesc(payload.agent_description);
      setDurationSeconds((performance.now() - t0) / 1000);
      setPhase('results');
      toast.success('Analysis complete!');
      refreshSessions(token);
    } catch (err) {
      setPhase('input');
      if (err instanceof Error && err.message === 'SESSION_EXPIRED') {
        toast.error('Session expired — please sign in again.');
        handleLogout();
        return;
      }
      toast.error(err instanceof Error ? err.message : 'Analysis failed. Is the backend running?');
    }
  }, [token, handleLogout, refreshSessions]);

  const handleQuickAnalyze = useCallback(async (config: QuickScanConfig) => {
    setVictimUrl(config.victim_url);
    setVictimModel(config.victim_model);
    setMaxPayloads(config.max_payloads_per_vuln);
    setLastConfig(config);

    if (config.adaptive_loop) {
      if (DEV_BYPASS_AUTH) { toast('Auth bypass is ON — connect a real backend to run analysis.'); return; }
      if (!token) { toast.error('Please sign in first.'); return; }
      setPhase('analyzing');
      setResults(null);
      setLoopResult(null);
      const t0 = performance.now();
      try {
        const data = await redTeamApi.runLoop(token, {
          agent_description:     config.description,
          uses_mcp:              config.uses_mcp,
          uses_rag:              config.uses_rag,
          victim_url:            config.victim_url || undefined,
          victim_model:          config.victim_model || undefined,
          max_payloads_per_vuln: config.max_payloads_per_vuln,
          ceiling:               config.ceiling,
          discovery_rounds:      config.discovery_rounds,
          probes_per_round:      config.probes_per_round,
          use_pair:              config.use_pair,
          pair_attempts:         config.pair_attempts,
          refiner_backend:       config.refiner_backend,
        });
        setLoopResult(data);
        setSubmittedDesc(config.description);
        setDurationSeconds((performance.now() - t0) / 1000);
        setPhase('results');
        if (data.stop_reason === 'agent_broken') toast.success('Agent broken — see results.');
        else if (data.stop_reason === 'ceiling_reached') toast(`Ceiling reached (${data.ceiling} rounds, no FAIL).`);
        else toast.error(`Loop stopped: ${data.stop_reason}`);
        refreshSessions(token);
      } catch (err) {
        setPhase('input');
        toast.error(err instanceof Error ? err.message : 'Adaptive loop failed.');
      }
      return;
    }
    return runAnalysis(analysisApi.buildQuickPayload(config.description, config.uses_mcp, config.uses_rag));
  }, [runAnalysis, token, refreshSessions]);

  const handleExpertAnalyze = useCallback(
    (config: ExpertConfig) => runAnalysis(analysisApi.buildExpertPayload(config)),
    [runAnalysis],
  );

  // -------------------------------------------------------------------------
  // Breadcrumb leaf
  // -------------------------------------------------------------------------
  const crumbLeaf = phase === 'input' ? 'New Analysis'
    : phase === 'analyzing' ? 'Analyzing…'
    : results?.agent_id ?? 'Results';

  // -------------------------------------------------------------------------
  // Render — unauthenticated
  // -------------------------------------------------------------------------
  if (isAuthLoading) {
    return (
      <div style={{
        minHeight: '100vh', background: 'var(--color-bg-base)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <Loader2 className="w-8 h-8 animate-spin" style={{ color: 'var(--color-accent)' }} />
      </div>
    );
  }

  if (!user) {
    return (
      <div style={{ minHeight: '100vh', background: 'var(--color-bg-base)' }}>
        {/* Simple top bar */}
        <header style={{
          height: 64, padding: '0 32px',
          display: 'flex', alignItems: 'center',
          background: '#fff', borderBottom: '1px solid var(--color-border)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 30, height: 30, borderRadius: 8,
              background: 'var(--color-accent)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <Shield size={16} color="#fff" />
            </div>
            <span style={{ fontSize: 15, fontWeight: 600, color: 'var(--color-text-primary)' }}>
              Agent Security Tester
            </span>
          </div>
        </header>

        <main style={{ maxWidth: 480, margin: '80px auto', padding: '0 24px' }}>
          <div style={{ textAlign: 'center', marginBottom: 32 }}>
            <h1 style={{ fontSize: 28, fontWeight: 700, color: 'var(--color-text-primary)', letterSpacing: '-0.02em' }}>
              Analyze your AI agent
            </h1>
            <p style={{ fontSize: 15, color: '#64748b', marginTop: 10, lineHeight: 1.6 }}>
              Describe what your agent does and we'll test it against the MAESTRO &amp; ATFAA threat frameworks.
            </p>
          </div>
          <AuthModal onAuthenticated={handleAuthenticated} />
        </main>
      </div>
    );
  }

  // -------------------------------------------------------------------------
  // Render — authenticated (app shell)
  // -------------------------------------------------------------------------
  return (
    <AppShell
      user={user}
      view={view}
      onView={setView}
      onNewScan={handleNewScan}
      onLogout={handleLogout}
      sessions={sessions}
      activeSessionId={activeSession}
      onSession={handleOpenSession}
      crumbLeaf={crumbLeaf}
    >
      {/* ---- Dashboard ---- */}
      {view === 'dashboard' && <Dashboard token={token} />}

      {/* ---- Settings ---- */}
      {view === 'settings' && <Settings user={user} />}

      {/* ---- Workspace ---- */}
      {view === 'workspace' && (
        <div style={{
          flex: 1,
          display: 'flex',
          flexDirection: phase === 'input' ? 'column' : 'row',
          alignItems: phase === 'input' ? 'center' : 'flex-start',
          justifyContent: phase === 'input' ? 'flex-start' : undefined,
          gap: 24,
          padding: phase === 'input' ? '56px 32px 64px' : '24px',
          maxWidth: phase !== 'input' ? 1180 : undefined,
          margin: phase !== 'input' ? '0 auto' : undefined,
          width: '100%',
        }}>

          {/* Hero — input phase only */}
          {phase === 'input' && (
            <div style={{ textAlign: 'center', maxWidth: 560, animation: 'fadeUp .4s ease' }}>
              <div style={{
                width: 56, height: 56, borderRadius: 16,
                background: 'var(--color-accent-soft)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                margin: '0 auto 18px',
              }}>
                <Shield size={28} color="var(--color-accent)" />
              </div>
              <div style={{ fontSize: 28, fontWeight: 700, color: 'var(--color-text-primary)', letterSpacing: '-0.02em' }}>
                Analyze your AI agent
              </div>
              <div style={{ fontSize: 15, color: '#64748b', marginTop: 10, lineHeight: 1.6 }}>
                Describe what your agent does and we'll test it against the MAESTRO &amp; ATFAA threat frameworks.
              </div>
            </div>
          )}

          {/* Form card — stays sticky left when in results phase */}
          <div style={{
            width: phase === 'input' ? '100%' : 360,
            maxWidth: phase === 'input' ? 560 : undefined,
            flexShrink: 0,
            position: phase === 'results' ? 'sticky' : undefined,
            top: phase === 'results' ? 80 : undefined,
          }}>
            <div style={{
              background: '#fff',
              border: '1px solid var(--color-border)',
              borderRadius: 16,
              padding: 24,
              boxShadow: 'var(--shadow-card)',
            }}>
              <ModeSelector mode={analysisMode} onChange={setAnalysisMode} />

              {analysisMode === 'quick' ? (
                <QuickAnalysis
                  onAnalyze={handleQuickAnalyze}
                  isAnalyzing={phase === 'analyzing'}
                />
              ) : (
                <ExpertAnalysis
                  onAnalyze={handleExpertAnalyze}
                  isAnalyzing={phase === 'analyzing'}
                />
              )}
            </div>
          </div>

          {/* Right panel — analyzing or results */}
          {phase !== 'input' && (
            <div style={{ flex: 1, minWidth: 0, animation: 'fadeUp .45s ease' }}>
              {phase === 'analyzing' && (
                <AnalyzingPanel
                  usesMcp={lastConfig?.uses_mcp}
                  usesRag={lastConfig?.uses_rag}
                />
              )}

              {phase === 'results' && (
                <>
                  {results && !loopResult && (
                    <ResultsDisplay
                      results={results}
                      durationSeconds={durationSeconds ?? undefined}
                      mode={resultMode}
                      token={token}
                      agentDescription={submittedDesc}
                      victimUrl={victimUrl}
                      victimModel={victimModel}
                      maxPayloadsPerVuln={maxPayloads}
                    />
                  )}

                  {loopResult && (
                    <div className="space-y-4">
                      {/* Adaptive-loop header */}
                      <div style={{
                        background: '#fff', border: '1px solid var(--color-border)',
                        borderRadius: 14, padding: 20,
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--color-text-primary)', margin: 0 }}>
                              Adaptive Black-Box Loop
                            </h3>
                            {loopResult.engine?.attack_method === 'PAIR' && (
                              <span style={{
                                fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 9999,
                                background: '#f5f3ff', color: '#7c3aed',
                              }}>
                                PAIR · {loopResult.engine.refiner_backend || 'local'}
                              </span>
                            )}
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <button
                              onClick={() => {
                                const blob = new Blob([JSON.stringify(loopResult, null, 2)], { type: 'application/json' });
                                const url = URL.createObjectURL(blob);
                                const a = document.createElement('a');
                                a.href = url; a.download = `redteam-loop-${Date.now()}.json`; a.click();
                                URL.revokeObjectURL(url);
                              }}
                              className="btn-ghost"
                            >
                              Download JSON
                            </button>
                            <span style={{
                              fontSize: 11, fontWeight: 700, padding: '3px 8px', borderRadius: 9999,
                              background: loopResult.stop_reason === 'agent_broken' ? 'var(--color-critical-bg)' : '#f8fafc',
                              color:      loopResult.stop_reason === 'agent_broken' ? 'var(--color-critical)' : '#64748b',
                            }}>
                              {loopResult.stop_reason.replace(/_/g, ' ').toUpperCase()}
                            </span>
                          </div>
                        </div>
                        <p style={{ fontSize: 12, color: '#94a3b8', margin: 0 }}>
                          Discovery probes: {loopResult.recon.probes.length}
                          {loopResult.discovery && <> across {loopResult.discovery.rounds.length} round{loopResult.discovery.rounds.length === 1 ? '' : 's'}</>} ·
                          Attack rounds: {loopResult.rounds.length}/{loopResult.ceiling} ·
                          Duration: {loopResult.duration_seconds.toFixed(1)}s
                        </p>
                      </div>

                      {/* Discovery */}
                      <div style={{
                        borderRadius: 12, padding: 16,
                        background: '#faf5ff', border: '1px solid #e9d5ff',
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                          <h4 style={{ fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em', color: '#7c3aed', margin: 0 }}>
                            Black-box discovery
                          </h4>
                          {loopResult.discovery && (
                            <span style={{ fontSize: 11, fontFamily: 'monospace', color: '#a78bfa' }}>
                              confidence {(loopResult.discovery.confidence * 100).toFixed(0)}%
                              {loopResult.discovery.uses_mcp && ' · MCP'}
                              {loopResult.discovery.uses_rag && ' · RAG'}
                            </span>
                          )}
                        </div>
                        {loopResult.discovery?.profile && (
                          <p style={{ fontSize: 12, fontStyle: 'italic', color: '#6d28d9', marginBottom: 8 }}>
                            "{loopResult.discovery.profile}"
                          </p>
                        )}
                        {!loopResult.discovery && (
                          <ul style={{ fontSize: 12, color: '#475569', margin: 0, paddingLeft: 16 }}>
                            {loopResult.recon.learnings.map((l, i) => <li key={i}>{l}</li>)}
                          </ul>
                        )}
                      </div>

                      {/* Rounds table */}
                      <div style={{ background: '#fff', border: '1px solid var(--color-border)', borderRadius: 12, overflow: 'hidden' }}>
                        <table style={{ width: '100%', fontSize: 12, borderCollapse: 'collapse' }}>
                          <thead>
                            <tr style={{ background: 'var(--color-bg-base)', color: '#94a3b8' }}>
                              {['Round','Tested','Refused','Complied','Unknown','Time','Broken?'].map(h => (
                                <th key={h} style={{ textAlign: h === 'Round' ? 'left' : 'right', padding: '10px 12px', fontWeight: 600 }}>{h}</th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {loopResult.rounds.map(r => (
                              <tr key={r.round} style={{ borderTop: '1px solid var(--color-border)' }}>
                                <td style={{ padding: '10px 12px', fontFamily: 'monospace' }}>{r.round}</td>
                                <td style={{ padding: '10px 12px', textAlign: 'right' }}>{r.tested}</td>
                                <td style={{ padding: '10px 12px', textAlign: 'right', color: 'var(--color-success)' }}>{r.refused}</td>
                                <td style={{ padding: '10px 12px', textAlign: 'right', color: 'var(--color-critical)' }}>{r.complied}</td>
                                <td style={{ padding: '10px 12px', textAlign: 'right', color: '#94a3b8' }}>{r.unknown}</td>
                                <td style={{ padding: '10px 12px', textAlign: 'right' }}>{r.duration_seconds.toFixed(1)}s</td>
                                <td style={{ padding: '10px 12px', textAlign: 'center' }}>{r.broken ? '🟥 yes' : '✅ no'}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>

                      {loopResult.analysis && loopResult.evaluation && (
                        <ResultsDisplay
                          results={loopResult.analysis}
                          mode="quick"
                          durationSeconds={loopResult.duration_seconds}
                          token={token}
                          agentDescription={submittedDesc}
                          victimUrl={victimUrl}
                          victimModel={victimModel}
                          maxPayloadsPerVuln={maxPayloads}
                          precomputedPayloads={loopResult.payloads}
                          precomputedEval={loopResult.evaluation}
                        />
                      )}
                    </div>
                  )}
                </>
              )}
            </div>
          )}
        </div>
      )}
    </AppShell>
  );
}
