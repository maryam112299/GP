'use client';

import Link from 'next/link';
import { motion } from 'framer-motion';
import { Shield, Lock, UserRound, LogOut, Zap } from 'lucide-react';
import type { UserProfile } from '@/types';

interface HeaderProps {
  user: UserProfile | null;
  onLogout: () => void;
}

export default function Header({ user, onLogout }: HeaderProps) {
  const displayName = user
    ? `${user.first_name} ${user.last_name}`.trim() || user.email
    : '';

  return (
    <header className="relative z-20 border-b border-white/5 backdrop-blur-md" style={{ background: 'rgba(8,12,18,0.85)' }}>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4">
        <motion.div
          initial={{ opacity: 0, y: -16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="flex items-center justify-between"
        >
          {/* Brand */}
          <Link href="/" className="flex items-center gap-3 group">
            <div className="relative flex-shrink-0">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center"
                   style={{ background: 'linear-gradient(135deg,#06d6a0,#0ea5e9)' }}>
                <Shield className="w-5 h-5 text-white" />
              </div>
              <div className="absolute -bottom-1 -right-1 w-4 h-4 rounded-full flex items-center justify-center"
                   style={{ background: '#080c12', border: '1px solid rgba(6,214,160,0.4)' }}>
                <Lock className="w-2.5 h-2.5" style={{ color: '#06d6a0' }} />
              </div>
            </div>
            <div>
              <h1 className="text-base font-700 text-white leading-tight tracking-tight group-hover:opacity-90 transition-opacity">
                AI Security Tester
              </h1>
              <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
                MAESTRO & ATFAA Frameworks
              </p>
            </div>
          </Link>

          {/* Nav */}
          <div className="flex items-center gap-2">
            {user ? (
              <>
                <Link
                  href="/profile"
                  className="btn-ghost text-sm flex items-center gap-2"
                  style={{ color: 'var(--color-accent-green)', borderColor: 'var(--color-border-accent)' }}
                >
                  <UserRound className="w-4 h-4" />
                  <span className="hidden sm:inline">{displayName}</span>
                </Link>
                <button onClick={onLogout} className="btn-danger">
                  <LogOut className="w-4 h-4" />
                  <span className="hidden sm:inline text-sm">Logout</span>
                </button>
              </>
            ) : (
              <div className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-full"
                   style={{ background: 'var(--color-bg-elevated)', color: 'var(--color-text-muted)', border: '1px solid var(--color-border)' }}>
                <Zap className="w-3.5 h-3.5" />
                Sign in to analyse
              </div>
            )}
          </div>
        </motion.div>
      </div>
    </header>
  );
}
