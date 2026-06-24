'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Mail, Lock, User, Eye, EyeOff, Shield, ArrowRight, Loader2 } from 'lucide-react';
import { authApi, parseErrorMessage } from '@/lib/api';
import type { UserProfile } from '@/types';
import toast from 'react-hot-toast';

interface AuthModalProps {
  onAuthenticated: (token: string, user: UserProfile) => void;
}

type Mode = 'login' | 'signup';

interface FormState {
  fullName: string;
  email: string;
  password: string;
}

export default function AuthModal({ onAuthenticated }: AuthModalProps) {
  const [mode, setMode] = useState<Mode>('login');
  const [form, setForm] = useState<FormState>({ fullName: '', email: '', password: '' });
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  const update = (field: keyof FormState) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((prev) => ({ ...prev, [field]: e.target.value }));

  const switchMode = (next: Mode) => {
    setMode(next);
    setForm({ fullName: '', email: '', password: '' });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    try {
      const data =
        mode === 'login'
          ? await authApi.login(form.email, form.password)
          : await authApi.signup(form.fullName, form.email, form.password);

      localStorage.setItem('auth_token', data.access_token);
      toast.success(mode === 'login' ? 'Welcome back!' : 'Account created!');
      onAuthenticated(data.access_token, data.user);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Authentication failed');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto">
      {/* Card */}
      <motion.div
        initial={{ opacity: 0, y: 24, scale: 0.97 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
        className="glass-card p-6 md:p-8 rounded-2xl"
        style={{ boxShadow: '0 0 0 1px rgba(6,214,160,0.1), 0 24px 64px rgba(0,0,0,0.5)' }}
      >
        {/* Header */}
        <div className="text-center mb-8">
          <div className="w-12 h-12 rounded-2xl mx-auto mb-4 flex items-center justify-center"
               style={{ background: '#1d4ed8', boxShadow: '0 8px 24px rgba(29,78,216,0.3)' }}>
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h2 className="text-2xl font-bold text-white">
            {mode === 'login' ? 'Welcome back' : 'Create account'}
          </h2>
          <p className="text-sm mt-1" style={{ color: 'var(--color-text-secondary)' }}>
            {mode === 'login'
              ? 'Sign in to access your security workspace'
              : 'Join the AI security testing platform'}
          </p>
        </div>

        {/* Mode tabs */}
        <div className="flex p-1 rounded-xl mb-6" style={{ background: 'var(--color-bg-surface)' }}>
          {(['login', 'signup'] as Mode[]).map((tab) => (
            <button
              key={tab}
              onClick={() => switchMode(tab)}
              className="flex-1 py-2 rounded-lg text-sm font-medium transition-all duration-200"
              style={{
                background: mode === tab ? '#d3d6daff' : 'transparent',
                color: mode === tab ? 'var(--color-text-primary)' : 'var(--color-text-muted)',
                boxShadow: mode === tab ? 'var(--shadow-card)' : 'none',
              }}
            >
              {tab === 'login' ? 'Sign in' : 'Sign up'}
            </button>
          ))}
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <AnimatePresence mode="popLayout">
            {mode === 'signup' && (
              <motion.div
                key="fullname"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: 0.2 }}
              >
                <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
                  Full name
                </label>
                <div className="relative">
                  <User className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--color-text-muted)' }} />
                  <input
                    id="auth-full-name"
                    type="text"
                    placeholder="Jane Smith"
                    value={form.fullName}
                    onChange={update('fullName')}
                    className="input-base pl-10"
                    required
                    minLength={2}
                  />
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <div>
            <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
              Email address
            </label>
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--color-text-muted)' }} />
              <input
                id="auth-email"
                type="email"
                placeholder="you@company.com"
                value={form.email}
                onChange={update('email')}
                className="input-base pl-10"
                required
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4" style={{ color: 'var(--color-text-muted)' }} />
              <input
                id="auth-password"
                type={showPassword ? 'text' : 'password'}
                placeholder={mode === 'signup' ? 'At least 8 characters' : '••••••••'}
                value={form.password}
                onChange={update('password')}
                className="input-base pl-10 pr-10"
                required
                minLength={mode === 'signup' ? 8 : 1}
              />
              <button
                type="button"
                onClick={() => setShowPassword((p) => !p)}
                className="absolute right-3 top-1/2 -translate-y-1/2 transition-colors"
                style={{ color: 'var(--color-text-muted)' }}
              >
                {showPassword ? <Eye className="w-4 h-4" /> : <EyeOff className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <motion.button
            type="submit"
            disabled={isLoading}
            whileHover={{ scale: isLoading ? 1 : 1.015 }}
            whileTap={{ scale: isLoading ? 1 : 0.985 }}
            className="btn-primary w-full py-3 mt-2"
          >
            {isLoading ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <>
                <span>{mode === 'login' ? 'Sign in' : 'Create account'}</span>
                <ArrowRight className="w-4 h-4" />
              </>
            )}
          </motion.button>
        </form>
      </motion.div>
    </div>
  );
}
