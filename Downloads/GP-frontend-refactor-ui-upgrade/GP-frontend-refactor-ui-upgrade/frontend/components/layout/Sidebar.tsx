'use client';

import { Shield, Plus, Zap, LayoutDashboard, Settings, LogOut } from 'lucide-react';
import type { UserProfile } from '@/types';
import type { AppView } from './AppShell';

interface ScanSession {
  id: string;
  agent: string;
  date: string;
  score: number;
}

interface SidebarProps {
  user: UserProfile;
  view: AppView;
  onView: (v: AppView) => void;
  onNewScan: () => void;
  onLogout: () => void;
  sessions: ScanSession[];
  activeSessionId: string | null;
  onSession: (id: string) => void;
  isMobileOpen: boolean;
  onCloseMobile: () => void;
  isDesktopOpen: boolean;
  onToggleDesktop: () => void;
}

function riskBand(score: number): { color: string; label: string } {
  if (score >= 70) return { color: 'var(--color-risk-high)',   label: 'High' };
  if (score >= 40) return { color: 'var(--color-risk-medium)', label: 'Med' };
  return              { color: 'var(--color-risk-low)',    label: 'Low' };
}

export default function Sidebar({
  user, view, onView, onNewScan, onLogout,
  sessions, activeSessionId, onSession,
  isMobileOpen, onCloseMobile,
  isDesktopOpen, onToggleDesktop,
}: SidebarProps) {
  const displayName = `${user.first_name} ${user.last_name}`.trim() || user.email;
  const initials    = displayName.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase();

  const navItem = (v: AppView, Icon: React.ElementType, label: string) => {
    const active = view === v;
    return (
      <button
        onClick={() => onView(v)}
        style={{
          display: 'flex', alignItems: 'center', gap: 11,
          padding: '9px 12px', borderRadius: 10,
          fontSize: 13, fontWeight: 600, cursor: 'pointer',
          transition: 'all .15s', width: '100%', border: 'none',
          background: active ? 'var(--color-accent-soft)' : 'transparent',
          color: active ? 'var(--color-accent)' : '#475569',
        }}
      >
        <Icon size={16} color={active ? 'var(--color-accent)' : '#64748b'} />
        {label}
      </button>
    );
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {isMobileOpen && (
        <div 
          className="fixed inset-0 bg-black/20 z-40 md:hidden"
          onClick={onCloseMobile}
        />
      )}
      
      <aside className={`
        fixed inset-y-0 left-0 z-50 bg-white
        transition-all duration-300 ease-in-out
        h-screen md:sticky md:top-0
        ${isMobileOpen ? 'translate-x-0 w-[264px] border-r border-[var(--color-border)]' : '-translate-x-full w-[264px] border-r border-[var(--color-border)]'}
        ${isDesktopOpen ? 'md:translate-x-0 md:w-[264px]' : 'md:w-0 md:border-r-0 md:overflow-hidden md:opacity-0'}
      `}>
        <div className="w-[264px] flex flex-col h-full">
          {/* Logo */}
          <div style={{ padding: '18px 18px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{
                width: 30, height: 30, borderRadius: 8,
                background: 'var(--color-accent)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              }}>
                <Shield size={16} color="#fff" />
              </div>
              <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)' }}>
                Agent Security Tester
              </span>
            </div>
            {/* Desktop close button */}
            <button className="hidden md:flex text-[#94a3b8] p-1 hover:text-[#475569] transition-colors" onClick={onToggleDesktop}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><path d="M9 3v18"/><path d="m16 15-3-3 3-3"/>
              </svg>
            </button>
            {/* Mobile close button */}
            <button className="md:hidden text-[#94a3b8] p-1" onClick={onCloseMobile}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
              </svg>
            </button>
          </div>

          {/* New Scan */}
          <div style={{ padding: '0 14px 14px' }}>
            <button
              onClick={onNewScan}
              style={{
                width: '100%', height: 40, borderRadius: 10,
                background: 'var(--color-accent)', color: '#fff',
                fontSize: 13, fontWeight: 600, border: 'none',
                display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                cursor: 'pointer', transition: 'background .15s',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'var(--color-accent-hover)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'var(--color-accent)')}
            >
              <Plus size={15} />
              New Scan
            </button>
          </div>

      {/* Nav */}
      <div style={{ padding: '0 14px', display: 'flex', flexDirection: 'column', gap: 3 }}>
        {navItem('workspace', Zap, 'Workspace')}
        {navItem('dashboard', LayoutDashboard, 'Dashboard')}
      </div>

      {/* Recent Sessions */}
      <div style={{
        padding: '20px 22px 8px',
        fontSize: 11, fontWeight: 700, letterSpacing: '.08em',
        textTransform: 'uppercase', color: '#94a3b8',
      }}>
        Recent Sessions
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '0 14px', display: 'flex', flexDirection: 'column', gap: 4 }}>
        {sessions.length === 0 && (
          <p style={{ fontSize: 12, color: '#94a3b8', padding: '8px 12px' }}>No scans yet.</p>
        )}
        {sessions.map(s => {
          const band = riskBand(s.score);
          const sel  = activeSessionId === s.id && view === 'workspace';
          return (
            <button
              key={s.id}
              onClick={() => onSession(s.id)}
              style={{
                padding: '9px 12px', borderRadius: 10, cursor: 'pointer',
                background: sel ? 'var(--color-accent-soft)' : 'transparent',
                border: 'none', textAlign: 'left', transition: 'background .15s', width: '100%',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8 }}>
                <span style={{
                  fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                }}>
                  {s.agent}
                </span>
                <span style={{ width: 7, height: 7, borderRadius: '50%', background: band.color, flexShrink: 0 }} />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 3 }}>
                <span style={{ fontSize: 11, color: '#94a3b8' }}>{s.date}</span>
                <span style={{ fontSize: 11, color: '#cbd5e1' }}>·</span>
                <span style={{ fontSize: 11, fontWeight: 600, color: band.color }}>Risk {s.score}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Bottom: Settings + User */}
        <div style={{ borderTop: '1px solid var(--color-bg-base)', padding: '8px 14px 6px' }}>
          {navItem('settings', Settings, 'Settings')}

          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px', marginTop: 2, borderRadius: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: '50%',
              background: 'var(--color-accent-soft)', color: 'var(--color-accent)',
              fontSize: 12, fontWeight: 700,
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
            }}>
              {initials}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{
                fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)',
                whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
              }}>
                {displayName}
              </div>
              <div style={{ fontSize: 11, color: '#94a3b8' }}>{user.email}</div>
            </div>
            <button
              onClick={onLogout}
              title="Sign out"
              style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, flexShrink: 0 }}
            >
              <LogOut size={15} color="#94a3b8" />
            </button>
          </div>
        </div>
        </div>
      </aside>
    </>
  );
}
