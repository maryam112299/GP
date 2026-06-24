'use client';

import { Zap } from 'lucide-react';
import type { AnalysisMode } from '@/types';

interface ModeSelectorProps {
  mode: AnalysisMode;
  onChange: (mode: AnalysisMode) => void;
}

export default function ModeSelector({ mode, onChange }: ModeSelectorProps) {
  const tabBase: React.CSSProperties = {
    flex: 1, padding: '11px 0',
    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7,
    fontSize: 13, fontWeight: 600, cursor: 'pointer',
    transition: 'background .15s, color .15s',
    border: 'none',
  };

  return (
    <div style={{ display: 'flex', border: '1px solid var(--color-border)', borderRadius: 10, overflow: 'hidden', marginBottom: 20 }}>
      <button
        onClick={() => onChange('quick')}
        style={{
          ...tabBase,
          background: mode === 'quick' ? 'var(--color-accent)' : '#fff',
          color:      mode === 'quick' ? '#fff' : '#64748b',
        }}
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
          stroke={mode === 'quick' ? '#fff' : '#94a3b8'} strokeWidth="2"
          strokeLinecap="round" strokeLinejoin="round">
          <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
        </svg>
        Quick
      </button>
      <button
        onClick={() => onChange('expert')}
        style={{
          ...tabBase,
          borderLeft: '1px solid var(--color-border)',
          background: mode === 'expert' ? 'var(--color-accent)' : '#fff',
          color:      mode === 'expert' ? '#fff' : '#64748b',
        }}
      >
        <svg width="15" height="15" viewBox="0 0 24 24" fill="none"
          stroke={mode === 'expert' ? '#fff' : '#94a3b8'} strokeWidth="2"
          strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 5a3 3 0 1 0-5.997.142 4 4 0 0 0-2.526 5.77 4 4 0 0 0 .556 6.588A4 4 0 1 0 12 18Z"/>
          <path d="M12 5a3 3 0 1 1 5.997.142 4 4 0 0 1 2.526 5.77 4 4 0 0 1-.556 6.588A4 4 0 1 1 12 18Z"/>
        </svg>
        Expert
      </button>
    </div>
  );
}
