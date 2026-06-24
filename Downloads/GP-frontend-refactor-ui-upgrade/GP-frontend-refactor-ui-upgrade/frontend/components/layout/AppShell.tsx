'use client';

export type AppView = 'workspace' | 'dashboard' | 'settings';

import { useState } from 'react';
import Sidebar from './Sidebar';
import Topbar  from './Topbar';
import type { UserProfile } from '@/types';

interface ScanSession {
  id: string;
  agent: string;
  date: string;
  score: number;
}

interface AppShellProps {
  user: UserProfile;
  view: AppView;
  onView: (v: AppView) => void;
  onNewScan: () => void;
  onLogout: () => void;
  sessions: ScanSession[];
  activeSessionId: string | null;
  onSession: (id: string) => void;
  crumbLeaf: string;
  children: React.ReactNode;
}

export default function AppShell({
  user, view, onView, onNewScan, onLogout,
  sessions, activeSessionId, onSession,
  crumbLeaf, children,
}: AppShellProps) {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const [isDesktopSidebarOpen, setIsDesktopSidebarOpen] = useState(true);

  return (
    <div className="flex min-h-screen bg-[var(--color-bg-base)] font-sans relative">
      <Sidebar
        user={user}
        view={view}
        onView={(v) => { onView(v); setIsMobileMenuOpen(false); }}
        onNewScan={() => { onNewScan(); setIsMobileMenuOpen(false); }}
        onLogout={onLogout}
        sessions={sessions}
        activeSessionId={activeSessionId}
        onSession={(id) => { onSession(id); setIsMobileMenuOpen(false); }}
        isMobileOpen={isMobileMenuOpen}
        onCloseMobile={() => setIsMobileMenuOpen(false)}
        isDesktopOpen={isDesktopSidebarOpen}
        onToggleDesktop={() => setIsDesktopSidebarOpen(prev => !prev)}
      />
      <div className="flex-1 min-w-0 flex flex-col transition-all duration-300">
        <Topbar 
          view={view} 
          crumbLeaf={crumbLeaf} 
          onMenuClick={() => setIsMobileMenuOpen(true)}
          isDesktopOpen={isDesktopSidebarOpen}
          onToggleDesktop={() => setIsDesktopSidebarOpen(prev => !prev)}
        />
        <main className="flex-1 overflow-y-auto">
          {children}
        </main>
      </div>
    </div>
  );
}
