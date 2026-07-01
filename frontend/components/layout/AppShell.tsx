'use client';

export type AppView = 'workspace' | 'dashboard' | 'settings';

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
  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: 'var(--color-bg-base)', fontFamily: "'Outfit', sans-serif" }}>
      <Sidebar
        user={user}
        view={view}
        onView={onView}
        onNewScan={onNewScan}
        onLogout={onLogout}
        sessions={sessions}
        activeSessionId={activeSessionId}
        onSession={onSession}
      />
      <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
        <Topbar view={view} crumbLeaf={crumbLeaf} />
        <main style={{ flex: 1, overflowY: 'auto' }}>
          {children}
        </main>
      </div>
    </div>
  );
}
