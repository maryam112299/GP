'use client';

import { useEffect, useState, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Loader2 } from 'lucide-react';
import { authApi, analysisApi } from '@/lib/api';
import type { MissionFile, UserProfile, AnalysisMode, ExpertConfig } from '@/types';
import Header from '@/components/ui/Header';
import AuthModal from '@/components/auth/AuthModal';
import ModeSelector from '@/components/analysis/ModeSelector';
import QuickAnalysis from '@/components/analysis/QuickAnalysis';
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

  // -------------------------------------------------------------------------
  // Restore session on mount
  // -------------------------------------------------------------------------
  useEffect(() => {
    const stored = localStorage.getItem('auth_token');
    if (!stored) { setIsAuthLoading(false); return; }

    setToken(stored);
    authApi.me(stored)
      .then(setUser)
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

  const handleLogout = useCallback(() => {
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
    (description: string, uses_mcp: boolean, uses_rag: boolean) =>
      runAnalysis(analysisApi.buildQuickPayload(description, uses_mcp, uses_rag)),
    [runAnalysis],
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
              {results && !isAnalyzing && (
                <ResultsDisplay
                  results={results}
                  durationSeconds={durationSeconds ?? undefined}
                  mode={resultMode}
                />
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
