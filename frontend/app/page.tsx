'use client';

import { useEffect, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Loader2 } from 'lucide-react';
import { authApi, analysisApi, redTeamApi, type RedTeamLoopResponse } from '@/lib/api';
import type { MissionFile, UserProfile, AnalysisMode, ExpertConfig } from '@/types';
import Header from '@/components/ui/Header';
import AuthModal from '@/components/auth/AuthModal';
import ModeSelector from '@/components/analysis/ModeSelector';
import QuickAnalysis, { type QuickScanConfig } from '@/components/analysis/QuickAnalysis';
import ExpertAnalysis from '@/components/analysis/ExpertAnalysis';
import ResultsDisplay from '@/components/ResultsDisplay';
import toast from 'react-hot-toast';

export default function Home() {
  // Auth state
  const [token, setToken]         = useState('');
  const [user, setUser]           = useState<UserProfile | null>(null);
  const [isAuthLoading, setIsAuthLoading] = useState(true);

  // Analysis state
  const [analysisMode, setAnalysisMode] = useState<AnalysisMode>('quick');
  const [isAnalyzing, setIsAnalyzing]   = useState(false);
  const [results, setResults]           = useState<MissionFile | null>(null);
  const [resultMode, setResultMode]     = useState<AnalysisMode>('quick');
  const [durationSeconds, setDurationSeconds] = useState<number | null>(null);
  const [submittedDescription, setSubmittedDescription] = useState('');

  // Quick-mode "victim wiring" — flows from QuickAnalysis form into evaluate
  const [victimUrl,   setVictimUrl]   = useState('');
  const [victimModel, setVictimModel] = useState('');
  const [maxPayloads, setMaxPayloads] = useState(5);
  const [loopResult,  setLoopResult]  = useState<RedTeamLoopResponse | null>(null);

  // -------------------------------------------------------------------------
  // Restore session on mount
  // -------------------------------------------------------------------------
  useEffect(() => {
    // Try restoring session via cookie first; fall back to stored token
    const stored = localStorage.getItem('auth_token');

    authApi.me(stored ?? undefined)
      .then((profile) => {
        setUser(profile);
        if (stored) setToken(stored);
      })
      .catch(() => {
        localStorage.removeItem('auth_token');
        setToken('');
      })
      .finally(() => setIsAuthLoading(false));
  }, []);

  // -------------------------------------------------------------------------
  // Auth handlers
  // -------------------------------------------------------------------------
  const handleAuthenticated = useCallback((tok: string, profile: UserProfile) => {
    setToken(tok);
    setUser(profile);
  }, []);

  const handleLogout = useCallback(async () => {
    try { await authApi.logout(); } catch { /* best-effort */ }
    localStorage.removeItem('auth_token');
    setToken('');
    setUser(null);
    setResults(null);
  }, []);

  // -------------------------------------------------------------------------
  // Analysis handlers
  // -------------------------------------------------------------------------
  const runAnalysis = useCallback(
    async (payload: Parameters<typeof analysisApi.analyze>[1]) => {
      if (!token) { toast.error('Please sign in first.'); return; }

      setIsAnalyzing(true);
      setResults(null);
      setDurationSeconds(null);
      const t0 = performance.now();

      try {
        const data = await analysisApi.analyze(token, payload);
        setResults(data);
        setResultMode(payload.mode as AnalysisMode);
        setSubmittedDescription(payload.agent_description);
        setDurationSeconds((performance.now() - t0) / 1000);
        toast.success('Analysis complete!');
      } catch (err) {
        if (err instanceof Error && err.message === 'SESSION_EXPIRED') {
          toast.error('Session expired — please sign in again.');
          handleLogout();
          return;
        }
        toast.error(err instanceof Error ? err.message : 'Analysis failed. Is the backend running?');
      } finally {
        setIsAnalyzing(false);
      }
    },
    [token, handleLogout],
  );

  const handleQuickAnalyze = useCallback(
    async (config: QuickScanConfig) => {
      // Capture victim wiring before kicking off — ResultsDisplay reads these.
      setVictimUrl(config.victim_url);
      setVictimModel(config.victim_model);
      setMaxPayloads(config.max_payloads_per_vuln);

      // Adaptive loop branch — call the new endpoint, render its result.
      if (config.adaptive_loop) {
        if (!token) { toast.error('Please sign in first.'); return; }
        setIsAnalyzing(true);
        setResults(null);
        setLoopResult(null);
        setDurationSeconds(null);
        const t0 = performance.now();
        try {
          const data = await redTeamApi.runLoop(token, {
            agent_description: config.description,
            uses_mcp:          config.uses_mcp,
            uses_rag:          config.uses_rag,
            victim_url:        config.victim_url || undefined,
            victim_model:      config.victim_model || undefined,
            max_payloads_per_vuln: config.max_payloads_per_vuln,
            ceiling:           config.ceiling,
            discovery_rounds:  config.discovery_rounds,
            probes_per_round:  config.probes_per_round,
            use_pair:          config.use_pair,
            pair_attempts:     config.pair_attempts,
            refiner_backend:   config.refiner_backend,
          });
          setLoopResult(data);
          setSubmittedDescription(config.description);
          setDurationSeconds((performance.now() - t0) / 1000);
          if (data.stop_reason === 'agent_broken') toast.success('Agent broken — see results.');
          else if (data.stop_reason === 'ceiling_reached') toast(`Ceiling reached (${data.ceiling} rounds, no FAIL).`);
          else toast.error(`Loop stopped: ${data.stop_reason}`);
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Adaptive loop failed.');
        } finally {
          setIsAnalyzing(false);
        }
        return;
      }

      return runAnalysis(
        analysisApi.buildQuickPayload(config.description, config.uses_mcp, config.uses_rag),
      );
    },
    [runAnalysis, token],
  );

  const handleExpertAnalyze = useCallback(
    (config: ExpertConfig) => runAnalysis(analysisApi.buildExpertPayload(config)),
    [runAnalysis],
  );

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------
  return (
    <div className="min-h-screen" style={{ background: 'var(--color-bg-base)' }}>
      {/* Background decoration */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden" aria-hidden>
        <div className="blob w-96 h-96 top-0 -left-20"  style={{ background: '#06d6a0' }} />
        <div className="blob w-96 h-96 top-1/3 -right-20" style={{ background: '#0ea5e9', animationDelay: '3s' }} />
        <div className="blob w-80 h-80 bottom-0 left-1/2" style={{ background: '#a78bfa', animationDelay: '6s' }} />
      </div>

      <Header user={user} onLogout={handleLogout} />

      <main className="relative z-10 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        {/* Auth loading */}
        {isAuthLoading && (
          <div className="flex items-center justify-center py-32">
            <Loader2 className="w-8 h-8 animate-spin" style={{ color: 'var(--color-accent-green)' }} />
          </div>
        )}

        {/* Unauthenticated */}
        {!isAuthLoading && !user && (
          <div>
            {/* Hero */}
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="text-center mb-12"
            >
              <h2 className="text-4xl sm:text-5xl font-bold text-white mb-4 leading-tight">
                Find vulnerabilities in{' '}
                <span className="gradient-text">AI agents</span>{' '}
                before attackers do.
              </h2>
              <p className="text-lg max-w-2xl mx-auto" style={{ color: 'var(--color-text-secondary)' }}>
                Powered by MAESTRO layer decomposition and ATFAA behavioral threat analysis.
                Supports Quick and Expert scanning modes.
              </p>
            </motion.div>

            <AuthModal onAuthenticated={handleAuthenticated} />
          </div>
        )}

        {/* Authenticated */}
        {!isAuthLoading && user && (
          <>
            {/* Analysis card */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.4 }}
              className="glass-card p-6"
            >
              <div className="mb-5">
                <h2 className="text-xl font-bold text-white">Security Analysis</h2>
                <p className="text-sm mt-0.5" style={{ color: 'var(--color-text-secondary)' }}>
                  Choose a mode and describe the AI agent you want to test.
                </p>
              </div>

              <ModeSelector mode={analysisMode} onChange={setAnalysisMode} />

              <AnimatePresence mode="wait">
                {analysisMode === 'quick' ? (
                  <motion.div
                    key="quick"
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 8 }}
                    transition={{ duration: 0.2 }}
                  >
                    <QuickAnalysis onAnalyze={handleQuickAnalyze} isAnalyzing={isAnalyzing} />
                  </motion.div>
                ) : (
                  <motion.div
                    key="expert"
                    initial={{ opacity: 0, x: 8 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: -8 }}
                    transition={{ duration: 0.2 }}
                  >
                    <ExpertAnalysis onAnalyze={handleExpertAnalyze} isAnalyzing={isAnalyzing} />
                  </motion.div>
                )}
              </AnimatePresence>
            </motion.div>

            {/* Analysing overlay */}
            <AnimatePresence>
              {isAnalyzing && (
                <motion.div
                  key="loading"
                  initial={{ opacity: 0, scale: 0.96 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.96 }}
                  className="mt-6 glass-card p-12 flex flex-col items-center gap-5"
                  style={{ borderColor: 'var(--color-border-accent)' }}
                >
                  <div className="relative">
                    <div className="w-16 h-16 rounded-full animate-glow"
                         style={{ background: 'radial-gradient(circle, rgba(6,214,160,0.3), transparent)' }} />
                    <Loader2 className="w-8 h-8 animate-spin absolute top-4 left-4"
                             style={{ color: 'var(--color-accent-green)' }} />
                  </div>
                  <div className="text-center">
                    <h3 className="text-lg font-semibold text-white">
                      {analysisMode === 'expert' ? 'Running Expert Analysis…' : 'Running Quick Analysis…'}
                    </h3>
                    <p className="text-sm mt-1" style={{ color: 'var(--color-text-muted)' }}>
                      Applying MAESTRO & ATFAA frameworks to identify vulnerabilities
                    </p>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Results */}
            <AnimatePresence>
              {results && !isAnalyzing && !loopResult && (
                <ResultsDisplay
                  results={results}
                  durationSeconds={durationSeconds ?? undefined}
                  mode={resultMode}
                  token={token}
                  agentDescription={submittedDescription}
                  victimUrl={victimUrl}
                  victimModel={victimModel}
                  maxPayloadsPerVuln={maxPayloads}
                />
              )}

              {loopResult && !isAnalyzing && (
                <div className="mt-4 glass-card p-6 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <h3 className="text-lg font-bold text-white">Adaptive Black-Box Loop</h3>
                      {loopResult.engine?.attack_method === 'PAIR' && (
                        <span
                          className="text-[10px] font-semibold px-2 py-0.5 rounded-full"
                          style={{ background: '#4c1d9544', color: '#c4b5fd' }}
                          title="PAIR closed-loop refinement: each payload is refined using the victim's reply + judge feedback"
                        >
                          PAIR · {loopResult.engine.refiner_backend || 'local'}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          const blob = new Blob([JSON.stringify(loopResult, null, 2)], { type: 'application/json' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `redteam-loop-${Date.now()}.json`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="btn-ghost text-xs py-1 px-3"
                        title="Download the full audit trail: every discovery probe + reply, synthesized intel, generated payload, and verdict"
                      >
                        Download full loop JSON
                      </button>
                      <span className="text-xs font-bold px-2 py-1 rounded-full" style={{
                        background: loopResult.stop_reason === 'agent_broken' ? '#7f1d1d44' : '#33415544',
                        color:      loopResult.stop_reason === 'agent_broken' ? '#fca5a5'  : '#cbd5e1',
                      }}>
                        {loopResult.stop_reason.replace(/_/g,' ').toUpperCase()}
                      </span>
                    </div>
                  </div>
                  <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                    Discovery probes: {loopResult.recon.probes.length}
                    {loopResult.discovery && <> across {loopResult.discovery.rounds.length} round{loopResult.discovery.rounds.length === 1 ? '' : 's'}</>} ·
                    Attack rounds: {loopResult.rounds.length}/{loopResult.ceiling} ·
                    Duration: {loopResult.duration_seconds.toFixed(1)}s
                  </p>

                  {/* Black-box discovery — what the agent learned by talking to the victim */}
                  <div className="rounded-lg p-3" style={{ background: 'rgba(139,92,246,0.07)', border: '1px solid rgba(139,92,246,0.25)' }}>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-xs uppercase tracking-wide font-semibold" style={{ color: '#c4b5fd' }}>
                        Black-box discovery
                      </h4>
                      {loopResult.discovery && (
                        <span className="text-[11px] font-mono" style={{ color: '#a78bfa' }}>
                          confidence {(loopResult.discovery.confidence * 100).toFixed(0)}%
                          {loopResult.discovery.uses_mcp && ' · MCP'}
                          {loopResult.discovery.uses_rag && ' · RAG'}
                        </span>
                      )}
                    </div>

                    {loopResult.discovery?.profile && (
                      <p className="text-xs mb-2 italic" style={{ color: '#ddd6fe' }}>
                        “{loopResult.discovery.profile}”
                      </p>
                    )}

                    {/* Discovered intel chips */}
                    {loopResult.discovery && (() => {
                      const di = loopResult.discovery.discovered_intel || {};
                      const chips: Array<{ k: string; v: string }> = [];
                      if (di.real_tool_names?.length)         chips.push({ k: 'tools',        v: di.real_tool_names.join(', ') });
                      if (di.account_id_schema)               chips.push({ k: 'id schema',    v: String(di.account_id_schema) });
                      if (di.employee_id_schema)              chips.push({ k: 'emp-id schema', v: String(di.employee_id_schema) });
                      if (di.ticket_id_patterns?.length)      chips.push({ k: 'ticket fmt',   v: di.ticket_id_patterns.join(', ') });
                      if (di.session_accounts?.length)        chips.push({ k: 'own ids',      v: di.session_accounts.join(', ') });
                      if (di.other_customer_accounts?.length) chips.push({ k: 'exfil targets', v: di.other_customer_accounts.join(', ') });
                      if (di.policy_summary)                  chips.push({ k: 'policy',       v: String(di.policy_summary) });
                      return chips.length ? (
                        <div className="flex flex-wrap gap-1.5 mb-2">
                          {chips.map((c, i) => (
                            <span key={i} className="text-[11px] px-2 py-0.5 rounded-full font-mono"
                                  style={{ background: 'rgba(255,255,255,0.06)', color: '#e9d5ff', border: '1px solid rgba(255,255,255,0.08)' }}>
                              <span style={{ color: '#a78bfa' }}>{c.k}:</span> {c.v}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="text-[11px] mb-2" style={{ color: '#94a3b8' }}>
                          No structured identifiers extracted — the victim revealed little; payloads fall back to its description.
                        </p>
                      );
                    })()}

                    {loopResult.discovery?.discovered_intel?.promising_attack_angles?.length ? (
                      <ul className="text-[11px] space-y-0.5 mb-2" style={{ color: '#cbd5e1' }}>
                        {loopResult.discovery.discovered_intel.promising_attack_angles.slice(0, 5).map((a, i) => (
                          <li key={i}>↳ {a}</li>
                        ))}
                      </ul>
                    ) : null}

                    {/* Per-round probe/reply transcript */}
                    {loopResult.discovery?.rounds.map((rd) => (
                      <details key={rd.round} className="mt-1.5">
                        <summary className="text-[11px] cursor-pointer select-none" style={{ color: '#a78bfa' }}>
                          Round {rd.round}: {rd.probes.length} probe{rd.probes.length === 1 ? '' : 's'}
                          {' '}· conf {(rd.confidence * 100).toFixed(0)}%{rd.enough ? ' · sufficient' : ''}
                        </summary>
                        <div className="mt-1.5 space-y-1.5 pl-3">
                          {rd.probes.map((p, i) => (
                            <div key={i} className="text-[11px]">
                              <p style={{ color: '#93c5fd' }}><span className="font-semibold">Q:</span> {p.probe}</p>
                              <p style={{ color: '#cbd5e1' }}><span className="font-semibold" style={{ color: '#6ee7b7' }}>A:</span> {p.reply.slice(0, 400)}{p.reply.length > 400 ? '…' : ''}</p>
                            </div>
                          ))}
                        </div>
                      </details>
                    ))}

                    {/* Fallback when discovery object absent (older backend) */}
                    {!loopResult.discovery && (
                      <ul className="text-xs space-y-1" style={{ color: '#cbd5e1' }}>
                        {loopResult.recon.learnings.map((l, i) => <li key={i}>{l}</li>)}
                      </ul>
                    )}
                  </div>

                  <div>
                    <h4 className="text-xs uppercase tracking-wide font-semibold mb-2" style={{ color: '#94a3b8' }}>
                      Rounds
                    </h4>
                    <div className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--color-border)' }}>
                      <table className="w-full text-xs">
                        <thead style={{ background: 'rgba(255,255,255,0.04)', color: '#94a3b8' }}>
                          <tr>
                            <th className="text-left p-2">Round</th>
                            <th className="text-right p-2">Tested</th>
                            <th className="text-right p-2" style={{ color: '#6ee7b7' }}>Refused</th>
                            <th className="text-right p-2" style={{ color: '#fca5a5' }}>Complied</th>
                            <th className="text-right p-2">Unknown</th>
                            <th className="text-right p-2">Time</th>
                            <th className="text-center p-2">Broken?</th>
                          </tr>
                        </thead>
                        <tbody>
                          {loopResult.rounds.map(r => (
                            <tr key={r.round} style={{ borderTop: '1px solid var(--color-border)' }}>
                              <td className="p-2 font-mono">{r.round}</td>
                              <td className="p-2 text-right">{r.tested}</td>
                              <td className="p-2 text-right" style={{ color: '#6ee7b7' }}>{r.refused}</td>
                              <td className="p-2 text-right" style={{ color: '#fca5a5' }}>{r.complied}</td>
                              <td className="p-2 text-right" style={{ color: '#94a3b8' }}>{r.unknown}</td>
                              <td className="p-2 text-right">{r.duration_seconds.toFixed(1)}s</td>
                              <td className="p-2 text-center">{r.broken ? '🟥 yes' : '✅ no'}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>

                  {loopResult.analysis && loopResult.evaluation && (
                    <ResultsDisplay
                      results={loopResult.analysis}
                      mode="quick"
                      durationSeconds={loopResult.duration_seconds}
                      token={token}
                      agentDescription={submittedDescription}
                      victimUrl={victimUrl}
                      victimModel={victimModel}
                      maxPayloadsPerVuln={maxPayloads}
                      precomputedPayloads={loopResult.payloads}
                      precomputedEval={loopResult.evaluation}
                    />
                  )}
                </div>
              )}
            </AnimatePresence>
          </>
        )}
      </main>

      <footer className="relative z-10 border-t mt-20 py-6 text-center text-xs"
              style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
        AI Agent Security Tester · MAESTRO & ATFAA Frameworks · {new Date().getFullYear()}
      </footer>
    </div>
  );
}
