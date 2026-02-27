'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { ArrowLeft, Loader2, LogOut, UserRound } from 'lucide-react';
import toast from 'react-hot-toast';
import type { ScanRecord, ScanHistoryResponse } from '@/types';

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

type ProfileFormState = {
  email: string;
  first_name: string;
  last_name: string;
  mobile_number: string;
  company_name: string;
  job_role: string;
  country: string;
};

const emptyProfileForm: ProfileFormState = {
  email: '',
  first_name: '',
  last_name: '',
  mobile_number: '',
  company_name: '',
  job_role: '',
  country: '',
};

const getErrorMessage = (data: any, fallback = 'Failed to update profile') => {
  const detail = data?.detail;

  if (typeof detail === 'string' && detail.trim()) {
    return detail;
  }

  if (Array.isArray(detail) && detail.length > 0) {
    const firstMessage = detail.find((item: any) => typeof item?.msg === 'string' && item.msg.trim());
    if (firstMessage?.msg) {
      return firstMessage.msg;
    }
  }

  return fallback;
};

export default function ProfilePage() {
  const [token, setToken] = useState('');
  const [user, setUser] = useState<UserProfile | null>(null);
  const [profileForm, setProfileForm] = useState<ProfileFormState>(emptyProfileForm);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [isLoadingScans, setIsLoadingScans] = useState(false);
  const [scanHistory, setScanHistory] = useState<ScanRecord[]>([]);

  const toProfileForm = (profile: UserProfile): ProfileFormState => ({
    email: profile.email || '',
    first_name: profile.first_name || '',
    last_name: profile.last_name || '',
    mobile_number: profile.mobile_number || '',
    company_name: profile.company_name || '',
    job_role: profile.job_role || '',
    country: profile.country || '',
  });

  useEffect(() => {
    const storedToken = localStorage.getItem('auth_token');
    if (!storedToken) {
      setIsLoading(false);
      return;
    }

    setToken(storedToken);
    fetch(`${API_BASE}/api/profile`, {
      headers: { Authorization: `Bearer ${storedToken}` },
    })
      .then(async (res) => {
        if (!res.ok) {
          throw new Error('Session expired');
        }

        const profile = await res.json();
        setUser(profile);
        setProfileForm(toProfileForm(profile));
      })
      .catch(() => {
        localStorage.removeItem('auth_token');
        setToken('');
        setUser(null);
      })
      .finally(() => setIsLoading(false));
  }, []);

  useEffect(() => {
    if (!token) {
      setScanHistory([]);
      return;
    }

    setIsLoadingScans(true);
    fetch(`${API_BASE}/api/scans`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(async (res) => {
        if (!res.ok) {
          throw new Error('Failed to load scan history');
        }

        const history: ScanHistoryResponse = await res.json();
        setScanHistory(history.scans || []);
      })
      .catch(() => {
        toast.error('Could not load scan history');
      })
      .finally(() => setIsLoadingScans(false));
  }, [token]);

  const handleProfileChange = (field: keyof ProfileFormState, value: string) => {
    setProfileForm((previous) => ({ ...previous, [field]: value }));
  };

  const saveProfile = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!token) {
      toast.error('Please log in first.');
      return;
    }

    setIsSaving(true);

    try {
      const response = await fetch(`${API_BASE}/api/profile`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(profileForm),
      });

      const data = await response.json();
      if (!response.ok) {
        throw new Error(getErrorMessage(data));
      }

      setUser(data);
      setProfileForm(toProfileForm(data));
      toast.success('Profile updated successfully');

      setIsLoadingScans(true);
      fetch(`${API_BASE}/api/scans`, {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then(async (res) => {
          if (!res.ok) {
            throw new Error('Failed to load scan history');
          }

          const history: ScanHistoryResponse = await res.json();
          setScanHistory(history.scans || []);
        })
        .catch(() => {
          toast.error('Could not refresh scan history');
        })
        .finally(() => setIsLoadingScans(false));
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to update profile';
      toast.error(message);
    } finally {
      setIsSaving(false);
    }
  };

  const logout = () => {
    localStorage.removeItem('auth_token');
    setToken('');
    setUser(null);
    setProfileForm(emptyProfileForm);
  };

  const displayName = user ? `${user.first_name} ${user.last_name}`.trim() || user.email : '';

  return (
    <main className="min-h-screen bg-gradient-to-br from-slate-900 via-green-900 to-slate-900 relative overflow-hidden">
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-20 left-10 w-72 h-72 bg-green-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-float"></div>
        <div className="absolute top-40 right-10 w-72 h-72 bg-cyan-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-float" style={{ animationDelay: '2s' }}></div>
      </div>

      <header className="relative z-10 border-b border-white/10 backdrop-blur-sm">
        <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <UserRound className="w-8 h-8 text-cyan-300" />
            <div>
              <h1 className="text-2xl font-bold text-white">Profile</h1>
              {user && <p className="text-sm text-gray-400">{displayName}</p>}
            </div>
          </div>

          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="flex items-center gap-2 px-3 py-2 rounded-lg border border-cyan-500/30 bg-cyan-500/20 text-cyan-200 hover:bg-cyan-500/30 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              <span className="text-sm">Back to Analysis</span>
            </Link>
            {user && (
              <button
                onClick={logout}
                className="flex items-center gap-2 px-3 py-2 rounded-lg border border-red-500/30 bg-red-500/20 text-red-300 hover:bg-red-500/30 transition-colors"
              >
                <LogOut className="w-4 h-4" />
                <span className="text-sm">Logout</span>
              </button>
            )}
          </div>
        </div>
      </header>

      <div className="relative z-10 max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        {isLoading ? (
          <div className="glass-dark rounded-xl p-10 border border-green-500/30 flex items-center justify-center">
            <Loader2 className="w-8 h-8 text-green-400 animate-spin" />
          </div>
        ) : !user ? (
          <div className="glass-dark rounded-xl p-8 border border-cyan-500/30">
            <h2 className="text-2xl font-bold text-white mb-2">Please log in first</h2>
            <p className="text-gray-400 mb-5">You need an authenticated session to view or edit your profile.</p>
            <Link
              href="/"
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-cyan-500 to-green-600 text-white font-semibold hover:from-cyan-600 hover:to-green-700"
            >
              Go to Home
            </Link>
          </div>
        ) : (
          <div className="space-y-8">
            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-dark rounded-xl p-6 border border-cyan-500/30">
              <p className="text-gray-400 mb-5 text-sm">Update your account profile details.</p>
              <form onSubmit={saveProfile} className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <input
                  type="text"
                  placeholder="First name"
                  value={profileForm.first_name}
                  onChange={(e) => handleProfileChange('first_name', e.target.value)}
                  className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  required
                />
                <input
                  type="text"
                  placeholder="Last name"
                  value={profileForm.last_name}
                  onChange={(e) => handleProfileChange('last_name', e.target.value)}
                  className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <input
                  type="email"
                  placeholder="Email"
                  value={profileForm.email}
                  onChange={(e) => handleProfileChange('email', e.target.value)}
                  className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                  required
                />
                <input
                  type="text"
                  placeholder="Mobile number"
                  value={profileForm.mobile_number}
                  onChange={(e) => handleProfileChange('mobile_number', e.target.value)}
                  className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <input
                  type="text"
                  placeholder="Company name"
                  value={profileForm.company_name}
                  onChange={(e) => handleProfileChange('company_name', e.target.value)}
                  className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <input
                  type="text"
                  placeholder="Job role"
                  value={profileForm.job_role}
                  onChange={(e) => handleProfileChange('job_role', e.target.value)}
                  className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500"
                />
                <input
                  type="text"
                  placeholder="Country"
                  value={profileForm.country}
                  onChange={(e) => handleProfileChange('country', e.target.value)}
                  className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 md:col-span-2"
                />

                <button
                  type="submit"
                  disabled={isSaving}
                  className={`md:col-span-2 py-3 rounded-lg text-white font-semibold transition-colors ${
                    isSaving
                      ? 'bg-gray-700 cursor-not-allowed'
                      : 'bg-gradient-to-r from-cyan-500 to-green-600 hover:from-cyan-600 hover:to-green-700'
                  }`}
                >
                  {isSaving ? 'Saving Profile...' : 'Save Profile'}
                </button>
              </form>
            </motion.div>

            <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="glass-dark rounded-xl p-6 border border-green-500/30">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-white">My Scan History</h2>
                {isLoadingScans && <Loader2 className="w-5 h-5 text-green-400 animate-spin" />}
              </div>

              {!isLoadingScans && scanHistory.length === 0 ? (
                <p className="text-gray-400 text-sm">No scans yet. Run an analysis from the main page and it will appear here.</p>
              ) : (
                <div className="space-y-4">
                  {scanHistory.map((scan) => (
                    <div key={scan.id} className="rounded-lg border border-gray-700/50 bg-slate-900/40 p-4">
                      <div className="flex flex-wrap items-center gap-3 mb-2">
                        <span className="text-xs px-2 py-1 rounded bg-green-500/20 text-green-300 border border-green-500/30">
                          {scan.duration_seconds.toFixed(2)}s
                        </span>
                        <span className="text-xs text-gray-400">
                          {new Date(scan.created_at).toLocaleString()}
                        </span>
                      </div>

                      <div className="mb-3">
                        <p className="text-xs text-gray-400 mb-1">Input</p>
                        <p className="text-sm text-gray-200 whitespace-pre-wrap">{scan.input_text}</p>
                      </div>

                      <div>
                        <p className="text-xs text-gray-400 mb-1">Output</p>
                        <p className="text-sm text-cyan-300 mb-1">Agent ID: {scan.output.agent_id}</p>
                        <p className="text-sm text-gray-300 mb-2">{scan.output.risk_summary}</p>
                        <p className="text-xs text-gray-400">Vulnerabilities: {scan.output.attack_plan.length}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          </div>
        )}
      </div>
    </main>
  );
}
