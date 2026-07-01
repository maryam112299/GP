'use client';

import { Bell, HelpCircle } from 'lucide-react';

export type AppView = 'workspace' | 'dashboard' | 'settings';

interface TopbarProps {
  view: AppView;
  crumbLeaf: string;
}

const ROOTS: Record<AppView, string> = {
  workspace: 'Workspace',
  dashboard: 'Dashboard',
  settings:  'Account',
};

const LEAVES: Record<AppView, string> = {
  dashboard: 'Overview',
  settings:  'Settings',
  workspace: '',  // overridden by crumbLeaf
};

export default function Topbar({ view, crumbLeaf }: TopbarProps) {
  const root = ROOTS[view];
  const leaf = view === 'workspace' ? crumbLeaf : LEAVES[view];

  return (
    <div style={{
      height: 56, flexShrink: 0,
      padding: '0 28px',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
      background: '#fff',
      borderBottom: '1px solid var(--color-border)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}>
        <span style={{ color: '#94a3b8' }}>{root}</span>
        <span style={{ color: '#cbd5e1' }}>/</span>
        <span style={{ color: 'var(--color-text-primary)', fontWeight: 600 }}>{leaf}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <Bell size={18} color="#94a3b8" style={{ cursor: 'pointer' }} />
        <HelpCircle size={18} color="#94a3b8" style={{ cursor: 'pointer' }} />
      </div>
    </div>
  );
}
