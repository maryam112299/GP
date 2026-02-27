'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Lock, Loader2, LogOut, UserRound } from 'lucide-react';
import { MissionFile } from '@/types';
import AgentInput from '@/components/AgentInput';
import ResultsDisplay from '@/components/ResultsDisplay';
import toast from 'react-hot-toast';

const API_BASE = 'http://localhost:8000';

type UserProfile = {
  id: string;
  email: string;
  first_name: string;
  last_name: string;
  mobile_number: string;
  company_name: string;
  job_role: string;
  country: string;
};

const getAuthErrorMessage = (data: any, fallback = 'Authentication failed') => {
  const detail = data?.detail;

  if (typeof detail === 'string' && detail.trim()) {
    return detail;
  }

  if (Array.isArray(detail) && detail.length > 0) {
    const passwordIssue = detail.find((item: any) => Array.isArray(item?.loc) && item.loc.includes('password'));
    if (passwordIssue) {
      return 'Password must be at least 8 characters long.';
    }

    const firstMessage = detail.find((item: any) => typeof item?.msg === 'string' && item.msg.trim());
    if (firstMessage?.msg) {
      return firstMessage.msg;
    }
  }

  return fallback;
};

export default function Home() {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisDurationSeconds, setAnalysisDurationSeconds] = useState<number | null>(null);
  const [results, setResults] = useState<MissionFile | null>(null);
  const [token, setToken] = useState<string>('');
  const [user, setUser] = useState<UserProfile | null>(null);
  const [isAuthLoading, setIsAuthLoading] = useState(true);
  const [authMode, setAuthMode] = useState<'login' | 'signup'>('login');
  const [authForm, setAuthForm] = useState({
    full_name: '',
    email: '',
    password: '',
  });

  const displayName = user
    ? `${user.first_name} ${user.last_name}`.trim() || user.email
    : '';

  useEffect(() => {
    const storedToken = localStorage.getItem('auth_token');
    if (!storedToken) {
      setIsAuthLoading(false);
      return;
    }

    setToken(storedToken);
    fetch(`${API_BASE}/api/auth/me`, {
      headers: { Authorization: `Bearer ${storedToken}` },
    })
      .then(async (res) => {
        if (!res.ok) {
          throw new Error('Session expired');
        }
        const me = await res.json();
        setUser(me);
      })
      .catch(() => {
        localStorage.removeItem('auth_token');
        setToken('');
        setUser(null);
      })
      .finally(() => setIsAuthLoading(false));
  }, []);

  const handleAnalyze = async (description: string) => {
    if (!token) {
      toast.error('Please log in first.');
      return;
    }

    setIsAnalyzing(true);
    setResults(null);
    setAnalysisDurationSeconds(null);
    const startedAt = performance.now();

    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ agent_description: description }),
      });

      if (!response.ok) {
        if (response.status === 401) {
          toast.error('Session expired. Please log in again.');
          localStorage.removeItem('auth_token');
          setToken('');
          setUser(null);
          return;
        }
        throw new Error('Analysis failed');
      }

      const data = await response.json();
      setResults(data);
      const duration = (performance.now() - startedAt) / 1000;
      setAnalysisDurationSeconds(duration);
      toast.success('Analysis completed successfully!');
    } catch (error) {
      console.error('Error:', error);
      toast.error('Failed to analyze agent. Make sure the backend is running.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const handleAuthSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const endpoint = authMode === 'login' ? '/api/auth/login' : '/api/auth/signup';
    const payload =
      authMode === 'login'
        ? { email: authForm.email, password: authForm.password }
        : {
            full_name: authForm.full_name,
            email: authForm.email,
            password: authForm.password,
          };

    try {
      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(getAuthErrorMessage(data));
      }

      setToken(data.access_token);
      setUser(data.user);
      localStorage.setItem('auth_token', data.access_token);
      setAuthForm({ full_name: '', email: '', password: '' });
      toast.success(authMode === 'login' ? 'Logged in successfully' : 'Account created successfully');
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Authentication failed';
      toast.error(message);
    }
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    setToken('');
    setUser(null);
    setResults(null);
  };

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 via-green-900 to-slate-900 relative overflow-hidden">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-10 w-72 h-72 bg-green-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-float"></div>
        <div className="absolute top-40 right-10 w-72 h-72 bg-cyan-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-float" style={{ animationDelay: '2s' }}></div>
        <div className="absolute -bottom-8 left-1/2 w-72 h-72 bg-green-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-float" style={{ animationDelay: '4s' }}></div>
      </div>

      <header className="relative z-10 border-b border-white/10 backdrop-blur-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <motion.div initial={{ opacity: 0, y: -20 }} animate={{ opacity: 1, y: 0 }} className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="relative">
                <Shield className="w-10 h-10 text-cyan-400" />
                <Lock className="w-5 h-5 text-green-400 absolute -bottom-1 -right-1" />
              </div>
              <div>
                <h1 className="text-3xl font-bold text-white tracking-tight">AI Agent Security Tester</h1>
                <p className="text-sm text-gray-400 mt-1">Breaking AI: Vulnerabilities in LLM and MCP Systems</p>
              </div>
            </div>

            {user ? (
              <div className="flex items-center gap-3">
                <Link
                  href="/profile"
                  className="flex items-center gap-2 text-green-300 bg-slate-900/40 px-3 py-2 rounded-lg border border-green-500/30 hover:bg-slate-900/60 transition-colors"
                >
                  <UserRound className="w-4 h-4" />
                  <span className="text-sm">{displayName}</span>
                </Link>
                <button
                  onClick={logout}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg border border-red-500/30 bg-red-500/20 text-red-300 hover:bg-red-500/30 transition-colors"
                >
                  <LogOut className="w-4 h-4" />
                  <span className="text-sm">Logout</span>
                </button>
              </div>
            ) : (
              <div className="text-sm text-gray-300">Please log in</div>
            )}
          </motion.div>
        </div>
      </header>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {isAuthLoading ? (
          <div className="glass-dark rounded-xl p-10 border border-green-500/30 flex items-center justify-center">
            <Loader2 className="w-8 h-8 text-green-400 animate-spin" />
          </div>
        ) : !user ? (
          <div className="max-w-xl mx-auto glass-dark rounded-xl p-8 border border-cyan-500/30">
            <h2 className="text-2xl font-bold text-white mb-2">{authMode === 'login' ? 'Login' : 'Create Account'}</h2>
            <p className="text-gray-400 mb-6">Use your account to access protected security analysis.</p>

            <form onSubmit={handleAuthSubmit} className="space-y-4">
              {authMode === 'signup' && (
                <input
                  type="text"
                  placeholder="Full name"
                  value={authForm.full_name}
                  onChange={(e) => setAuthForm((s) => ({ ...s, full_name: e.target.value }))}
                  className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  required
                />
              )}
              <input
                type="email"
                placeholder="Email"
                value={authForm.email}
                onChange={(e) => setAuthForm((s) => ({ ...s, email: e.target.value }))}
                className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                required
              />
              <input
                type="password"
                placeholder="Password"
                value={authForm.password}
                onChange={(e) => setAuthForm((s) => ({ ...s, password: e.target.value }))}
                className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                minLength={8}
                title="Password must be at least 8 characters"
                required
              />
              <button
                type="submit"
                className="w-full py-3 rounded-lg bg-gradient-to-r from-cyan-500 to-green-600 text-white font-semibold hover:from-cyan-600 hover:to-green-700"
              >
                {authMode === 'login' ? 'Login' : 'Create Account'}
              </button>
            </form>

            <button
              type="button"
              onClick={() => setAuthMode((m) => (m === 'login' ? 'signup' : 'login'))}
              className="mt-4 text-cyan-300 hover:text-cyan-200 text-sm"
            >
              {authMode === 'login' ? "Don't have an account? Sign up" : 'Already have an account? Login'}
            </button>
          </div>
        ) : (
          <>
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}>
              <AgentInput onAnalyze={handleAnalyze} isAnalyzing={isAnalyzing} />
            </motion.div>

            <AnimatePresence>
              {isAnalyzing && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.9 }}
                  className="mt-8 glass-dark rounded-xl p-12 border border-green-500/30"
                >
                  <div className="flex flex-col items-center justify-center space-y-4">
                    <Loader2 className="w-16 h-16 text-green-400 animate-spin" />
                    <div className="text-center">
                      <h3 className="text-xl font-semibold text-white mb-2">Analyzing Agent Security...</h3>
                      <p className="text-gray-400">Applying MAESTRO & ATFAA frameworks to identify vulnerabilities</p>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <AnimatePresence>
              {results && !isAnalyzing && (
                <ResultsDisplay
                  results={results}
                  durationSeconds={analysisDurationSeconds ?? undefined}
                />
              )}
            </AnimatePresence>
          </>
        )}
      </div>

      <footer className="relative z-10 border-t border-white/10 mt-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <p className="text-center text-gray-400 text-sm">AI Agent Security & Vulnerability Testing Platform • {new Date().getFullYear()}</p>
        </div>
      </footer>
    </main>
  );
}
