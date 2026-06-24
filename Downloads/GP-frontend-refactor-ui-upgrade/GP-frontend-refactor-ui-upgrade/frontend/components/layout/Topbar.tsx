'use client';

import { Bell, HelpCircle, Menu } from 'lucide-react';

export type AppView = 'workspace' | 'dashboard' | 'settings';

interface TopbarProps {
  view: AppView;
  crumbLeaf: string;
  onMenuClick: () => void;
  isDesktopOpen?: boolean;
  onToggleDesktop?: () => void;
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

export default function Topbar({ view, crumbLeaf, onMenuClick, isDesktopOpen = true, onToggleDesktop }: TopbarProps) {
  const root = ROOTS[view];
  const leaf = view === 'workspace' ? crumbLeaf : LEAVES[view];

  return (
    <div className="h-14 shrink-0 px-4 md:px-7 flex items-center justify-between bg-white border-b border-[var(--color-border)]">
      <div className="flex items-center gap-2 text-sm">
        {/* Mobile menu button */}
        <button className="md:hidden p-1 -ml-1 text-[#64748b]" onClick={onMenuClick}>
          <Menu size={20} />
        </button>

        {/* Desktop open button (only visible when sidebar is closed) */}
        {!isDesktopOpen && (
          <button className="hidden md:flex p-1 -ml-1 mr-2 text-[#94a3b8] hover:text-[#475569] transition-colors" onClick={onToggleDesktop}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect width="18" height="18" x="3" y="3" rx="2" ry="2"/><path d="M9 3v18"/><path d="m14 9 3 3-3 3"/>
            </svg>
          </button>
        )}

        <span className="hidden md:inline text-[#94a3b8]">{root}</span>
        <span className="hidden md:inline text-[#cbd5e1]">/</span>
        <span className="text-[var(--color-text-primary)] font-semibold truncate max-w-[200px] md:max-w-none">{leaf}</span>
      </div>
      <div className="flex items-center gap-3 md:gap-4">
        <Bell size={18} color="#94a3b8" className="cursor-pointer" />
        <HelpCircle size={18} color="#94a3b8" className="cursor-pointer hidden sm:block" />
      </div>
    </div>
  );
}
