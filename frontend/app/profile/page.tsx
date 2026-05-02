'use client';

import Link from 'next/link';
import { useEffect, useState, useCallback } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowLeft, Loader2, Save, Clock, Shield, Zap, Brain,
  User, Mail, Phone, Building2, Briefcase, Globe,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { profileApi, scansApi } from '@/lib/api';
import type { UserProfile, ScanRecord, ScanHistoryResponse, AnalysisMode } from '@/types';
import Header from '@/components/ui/Header';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type ProfileForm = Omit<UserProfile, 'id'>;

const EMPTY_FORM: ProfileForm = {
  email: '',
  first_name: '',
  last_name: '',
  mobile_number: '',
  company_name: '',
  job_role: '',
  country: '',
};

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function FormField({
  id, label, type = 'text', placeholder, value, onChange, required, icon: Icon,
}: {
  id: string;
  label: string;
  type?: string;
  placeholder?: string;
  value: string;
  onChange: (v: string) => void;
  required?: boolean;
  icon: React.ElementType;
}) {
  return (
    <div>
      <label htmlFor={id} className="block text-xs font-medium mb-1.5"
             style={{ color: 'var(--color-text-secondary)' }}>
        {label}{required && <span style={{ color: 'var(--color-accent-green)' }}> *</span>}
      </label>
      <div className="relative">
        <Icon className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4"
              style={{ color: 'var(--color-text-muted)' }} />
        <input
          id={id}
          type={type}
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          required={required}
          className="input-base pl-10 text-sm"
        />
      </div>
    </div>
  );
}

function ModeBadge({ mode }: { mode: AnalysisMode }) {
  const isExpert = mode === 'expert';
  return (
    <span
      className="badge"
      style={
        isExpert
          ? { background: 'rgba(167,139,250,0.12)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.25)' }
          : { background: 'rgba(6,214,160,0.12)',   color: '#06d6a0', border: '1px solid rgba(6,214,160,0.25)' }
      }
    >
      {isExpert ? <Brain className="w-3 h-3" /> : <Zap className="w-3 h-3" />}
      {isExpert ? 'Expert' : 'Quick'}
    </span>
  );
}

function ScanCard({ scan }: { scan: ScanRecord }) {
  const criticalCount = scan.output.attack_plan.filter((a) => a.priority === 'CRITICAL').length;
  const highCount     = scan.output.attack_plan.filter((a) => a.priority === 'HIGH').length;

  return (
    <div className="rounded-xl p-4" style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-center gap-2 flex-wrap">
          <ModeBadge mode={scan.mode ?? 'quick'} />
          <span className="flex items-center gap-1 text-xs" style={{ color: 'var(--color-text-muted)' }}>
            <Clock className="w-3 h-3" />
            {scan.duration_seconds.toFixed(2)}s
          </span>
          <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
            {new Date(scan.created_at).toLocaleString()}
          </span>
        </div>
        <div className="flex items-center gap-1.5 flex-shrink-0 text-xs">
          {criticalCount > 0 && (
            <span className="badge" style={{ background: 'rgba(248,81,73,0.12)', color: '#f85149', border: '1px solid rgba(248,81,73,0.25)' }}>
              {criticalCount} CRITICAL
            </span>
          )}
          {highCount > 0 && (
            <span className="badge" style={{ background: 'rgba(251,140,0,0.12)', color: '#fb8c00', border: '1px solid rgba(251,140,0,0.25)' }}>
              {highCount} HIGH
            </span>
          )}
        </div>
      </div>

      <p className="text-xs font-mono leading-relaxed line-clamp-2 mb-2"
         style={{ color: 'var(--color-text-secondary)' }}>
        {scan.input_text}
      </p>

      <div className="flex items-center gap-3 pt-2 border-t text-xs" style={{ borderColor: 'var(--color-border)' }}>
        <span className="font-mono" style={{ color: 'var(--color-accent-cyan)' }}>
          {scan.output.agent_id}
        </span>
        <span style={{ color: 'var(--color-text-muted)' }}>
          {scan.output.attack_plan.length} vulnerabilities
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ProfilePage() {
  const [token,        setToken]        = useState('');
  const [user,         setUser]         = useState<UserProfile | null>(null);
  const [form,         setForm]         = useState<ProfileForm>(EMPTY_FORM);
  const [isLoading,    setIsLoading]    = useState(true);
  const [isSaving,     setIsSaving]     = useState(false);
  const [scans,        setScans]        = useState<ScanRecord[]>([]);
  const [scansLoading, setScansLoading] = useState(false);

  // Map profile → form
  const profileToForm = (p: UserProfile): ProfileForm => ({
    email:         p.email         || '',
    first_name:    p.first_name    || '',
    last_name:     p.last_name     || '',
    mobile_number: p.mobile_number || '',
    company_name:  p.company_name  || '',
    job_role:      p.job_role      || '',
    country:       p.country       || '',
  });

  const updateField = (field: keyof ProfileForm) => (value: string) =>
    setForm((prev) => ({ ...prev, [field]: value }));

  // Fetch scan history
  const fetchScans = useCallback(async (tok: string) => {
    setScansLoading(true);
    try {
      const data: ScanHistoryResponse = await scansApi.getAll(tok);
      setScans(data.scans || []);
    } catch {
      toast.error('Could not load scan history.');
    } finally {
      setScansLoading(false);
    }
  }, []);

  // Restore session & fetch profile
  useEffect(() => {
    const stored = localStorage.getItem('auth_token');
    if (!stored) { setIsLoading(false); return; }

    setToken(stored);
    profileApi.get(stored)
      .then((profile) => {
        setUser(profile);
        setForm(profileToForm(profile));
        fetchScans(stored);
      })
      .catch(() => {
        localStorage.removeItem('auth_token');
        setToken('');
      })
      .finally(() => setIsLoading(false));
  }, [fetchScans]);

  const handleLogout = () => {
    localStorage.removeItem('auth_token');
    setToken('');
    setUser(null);
    setForm(EMPTY_FORM);
    setScans([]);
  };

  const saveProfile = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!token) { toast.error('Not authenticated.'); return; }

    setIsSaving(true);
    try {
      const updated = await profileApi.update(token, form);
      setUser(updated);
      setForm(profileToForm(updated));
      toast.success('Profile updated.');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to update profile.');
    } finally {
      setIsSaving(false);
    }
  };

  const displayName = user
    ? `${user.first_name} ${user.last_name}`.trim() || user.email
    : '';

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------
  return (
    <div className="min-h-screen" style={{ background: 'var(--color-bg-base)' }}>
      {/* Background blobs */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden" aria-hidden>
        <div className="blob w-80 h-80 top-0 -left-16"  style={{ background: '#06d6a0' }} />
        <div className="blob w-80 h-80 bottom-0 -right-16" style={{ background: '#0ea5e9', animationDelay: '3s' }} />
      </div>

      <Header user={user} onLogout={handleLogout} />

      <main className="relative z-10 max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-10">
        {/* Back link */}
        <Link href="/"
              className="inline-flex items-center gap-2 text-sm mb-6 transition-colors hover:opacity-80"
              style={{ color: 'var(--color-text-muted)' }}>
          <ArrowLeft className="w-4 h-4" />
          Back to Analysis
        </Link>

        {/* Loading */}
        {isLoading && (
          <div className="flex items-center justify-center py-32">
            <Loader2 className="w-8 h-8 animate-spin" style={{ color: 'var(--color-accent-green)' }} />
          </div>
        )}

        {/* Unauthenticated */}
        {!isLoading && !user && (
          <div className="glass-card p-8 text-center">
            <Shield className="w-10 h-10 mx-auto mb-4" style={{ color: 'var(--color-accent-green)' }} />
            <h2 className="text-xl font-bold text-white mb-2">Authentication Required</h2>
            <p className="mb-5 text-sm" style={{ color: 'var(--color-text-secondary)' }}>
              You need an active session to view or edit your profile.
            </p>
            <Link href="/" className="btn-primary inline-flex">
              Go to Sign In
            </Link>
          </div>
        )}

        {!isLoading && user && (
          <div className="space-y-6">
            {/* Profile header */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              className="glass-card p-6"
            >
              <div className="flex items-center gap-3 mb-6">
                <div className="w-10 h-10 rounded-xl flex items-center justify-center"
                     style={{ background: 'linear-gradient(135deg,#06d6a0,#0ea5e9)' }}>
                  <User className="w-5 h-5 text-white" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-white">{displayName}</h2>
                  <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>{user.email}</p>
                </div>
              </div>

              <form onSubmit={saveProfile} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <FormField id="profile-first-name"  label="First name"    value={form.first_name}    onChange={updateField('first_name')}    required icon={User}      placeholder="Jane" />
                  <FormField id="profile-last-name"   label="Last name"     value={form.last_name}     onChange={updateField('last_name')}                icon={User}      placeholder="Smith" />
                  <FormField id="profile-email"       label="Email address" value={form.email}         onChange={updateField('email')}         required icon={Mail}      type="email" placeholder="jane@company.com" />
                  <FormField id="profile-mobile"      label="Mobile number" value={form.mobile_number} onChange={updateField('mobile_number')}            icon={Phone}     placeholder="+1 555 000 0000" />
                  <FormField id="profile-company"     label="Company"       value={form.company_name}  onChange={updateField('company_name')}             icon={Building2} placeholder="Acme Corp" />
                  <FormField id="profile-job-role"    label="Job role"      value={form.job_role}      onChange={updateField('job_role')}                 icon={Briefcase} placeholder="Security Engineer" />
                  <div className="sm:col-span-2">
                    <FormField id="profile-country"   label="Country"       value={form.country}       onChange={updateField('country')}                  icon={Globe}     placeholder="United States" />
                  </div>
                </div>

                <div className="flex justify-end pt-2">
                  <motion.button
                    type="submit"
                    disabled={isSaving}
                    whileHover={{ scale: isSaving ? 1 : 1.02 }}
                    whileTap={{ scale: 0.98 }}
                    className="btn-primary"
                  >
                    {isSaving
                      ? <><Loader2 className="w-4 h-4 animate-spin" /> Saving…</>
                      : <><Save className="w-4 h-4" /> Save Profile</>
                    }
                  </motion.button>
                </div>
              </form>
            </motion.div>

            {/* Scan history */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 }}
              className="glass-card p-6"
            >
              <div className="flex items-center justify-between mb-5">
                <div className="flex items-center gap-2">
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center"
                       style={{ background: 'rgba(6,214,160,0.1)' }}>
                    <Shield className="w-4 h-4" style={{ color: 'var(--color-accent-green)' }} />
                  </div>
                  <div>
                    <h3 className="text-base font-bold text-white">Scan History</h3>
                    <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                      {scans.length} scan{scans.length !== 1 ? 's' : ''} total
                    </p>
                  </div>
                </div>
                {scansLoading && <Loader2 className="w-4 h-4 animate-spin" style={{ color: 'var(--color-accent-green)' }} />}
              </div>

              {!scansLoading && scans.length === 0 && (
                <div className="text-center py-10 rounded-xl" style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}>
                  <Shield className="w-8 h-8 mx-auto mb-3" style={{ color: 'var(--color-text-muted)' }} />
                  <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
                    No scans yet — run an analysis from the main page.
                  </p>
                </div>
              )}

              {scans.length > 0 && (
                <div className="space-y-3">
                  {scans.map((scan) => <ScanCard key={scan.id} scan={scan} />)}
                </div>
              )}
            </motion.div>
          </div>
        )}
      </main>

      <footer className="relative z-10 border-t mt-20 py-6 text-center text-xs"
              style={{ borderColor: 'var(--color-border)', color: 'var(--color-text-muted)' }}>
        AI Agent Security Tester · MAESTRO & ATFAA Frameworks · {new Date().getFullYear()}
      </footer>
    </div>
  );
}
