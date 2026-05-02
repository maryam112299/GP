'use client';

import { motion } from 'framer-motion';
import { Zap, Brain } from 'lucide-react';
import type { AnalysisMode } from '@/types';

interface ModeSelectorProps {
  mode: AnalysisMode;
  onChange: (mode: AnalysisMode) => void;
}

const modes = [
  {
    id: 'quick' as AnalysisMode,
    icon: Zap,
    label: 'Quick Mode',
    tagline: 'Instant analysis',
    description: 'Provide a brief agent description. The engine infers tools, data sources, and runs a focused threat scan — results in under 30 seconds.',
    color: '#06d6a0',
    gradient: 'linear-gradient(135deg, rgba(6,214,160,0.15), rgba(6,214,160,0.05))',
    border: 'rgba(6,214,160,0.3)',
  },
  {
    id: 'expert' as AnalysisMode,
    icon: Brain,
    label: 'Expert Mode',
    tagline: 'Deep analysis',
    description: 'Define every detail: agent identity, tools, data sources, architecture, and the exact vulnerability scope to probe. More thorough, more granular.',
    color: '#a78bfa',
    gradient: 'linear-gradient(135deg, rgba(167,139,250,0.15), rgba(167,139,250,0.05))',
    border: 'rgba(167,139,250,0.3)',
  },
] as const;

export default function ModeSelector({ mode, onChange }: ModeSelectorProps) {
  return (
    <div className="mb-6">
      <p className="text-xs font-medium uppercase tracking-widest mb-3" style={{ color: 'var(--color-text-muted)' }}>
        Analysis Mode
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {modes.map((m) => {
          const Icon = m.icon;
          const isActive = mode === m.id;
          return (
            <motion.button
              key={m.id}
              onClick={() => onChange(m.id)}
              whileHover={{ scale: 1.015 }}
              whileTap={{ scale: 0.985 }}
              className="text-left p-4 rounded-xl transition-all duration-200 relative overflow-hidden"
              style={{
                background: isActive ? m.gradient : 'var(--color-bg-elevated)',
                border: `1px solid ${isActive ? m.border : 'var(--color-border)'}`,
                boxShadow: isActive ? `0 0 20px ${m.color}1a` : 'none',
              }}
            >
              {isActive && (
                <motion.div
                  layoutId="mode-active-bg"
                  className="absolute inset-0 rounded-xl"
                  style={{ background: m.gradient }}
                  transition={{ type: 'spring', stiffness: 300, damping: 30 }}
                />
              )}
              <div className="relative z-10">
                <div className="flex items-center gap-2 mb-2">
                  <div className="w-7 h-7 rounded-lg flex items-center justify-center"
                       style={{ background: isActive ? `${m.color}25` : 'var(--color-bg-hover)' }}>
                    <Icon className="w-4 h-4" style={{ color: isActive ? m.color : 'var(--color-text-muted)' }} />
                  </div>
                  <div>
                    <span className="text-sm font-semibold" style={{ color: isActive ? m.color : 'var(--color-text-primary)' }}>
                      {m.label}
                    </span>
                    <span className="text-xs ml-1.5" style={{ color: 'var(--color-text-muted)' }}>
                      {m.tagline}
                    </span>
                  </div>
                  {isActive && (
                    <div className="ml-auto w-2 h-2 rounded-full" style={{ background: m.color }} />
                  )}
                </div>
                <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
                  {m.description}
                </p>
              </div>
            </motion.button>
          );
        })}
      </div>
    </div>
  );
}
