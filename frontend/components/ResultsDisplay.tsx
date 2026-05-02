'use client';

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Download, Shield, AlertTriangle, Info, Target, Crosshair,
  ChevronDown, ChevronUp, Clock, Zap, Brain,
} from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';
import { MissionFile, AttackObjective, type AnalysisMode } from '@/types';

interface ResultsDisplayProps {
  results: MissionFile;
  durationSeconds?: number;
  mode?: AnalysisMode;
}

// ---------------------------------------------------------------------------
// Priority config
// ---------------------------------------------------------------------------
const PRIORITY_CONFIG = {
  CRITICAL: { badge: 'badge-critical', dot: '#f85149', bg: 'rgba(248,81,73,0.06)' },
  HIGH:     { badge: 'badge-high',     dot: '#fb8c00', bg: 'rgba(251,140,0,0.06)' },
  MEDIUM:   { badge: 'badge-medium',   dot: '#f0c000', bg: 'rgba(240,192,0,0.06)' },
  LOW:      { badge: 'badge-low',      dot: '#58a6ff', bg: 'rgba(88,166,255,0.06)' },
} as const;

type Priority = keyof typeof PRIORITY_CONFIG;

// ---------------------------------------------------------------------------
// Summary bar
// ---------------------------------------------------------------------------
function SeveritySummary({ attacks }: { attacks: AttackObjective[] }) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  attacks.forEach((a) => { if (a.priority in counts) counts[a.priority as Priority]++; });
  const total = attacks.length || 1;

  return (
    <div className="mt-4">
      <div className="flex h-2 rounded-full overflow-hidden gap-0.5">
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Priority[]).map((p) =>
          counts[p] > 0 ? (
            <div
              key={p}
              style={{
                width: `${(counts[p] / total) * 100}%`,
                background: PRIORITY_CONFIG[p].dot,
                opacity: 0.8,
              }}
            />
          ) : null,
        )}
      </div>
      <div className="flex flex-wrap gap-3 mt-2">
        {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Priority[]).map((p) => (
          <div key={p} className="flex items-center gap-1.5 text-xs" style={{ color: 'var(--color-text-secondary)' }}>
            <span className="w-2 h-2 rounded-full" style={{ background: PRIORITY_CONFIG[p].dot }} />
            <span style={{ color: PRIORITY_CONFIG[p].dot }} className="font-semibold">{counts[p]}</span>
            {p.charAt(0) + p.slice(1).toLowerCase()}
          </div>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attack card (collapsible)
// ---------------------------------------------------------------------------
function AttackCard({ attack, index }: { attack: AttackObjective; index: number }) {
  const [open, setOpen] = useState(index < 3); // first 3 pre-expanded
  const cfg = PRIORITY_CONFIG[attack.priority as Priority] ?? PRIORITY_CONFIG.LOW;

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.06, duration: 0.3 }}
      className="rounded-xl overflow-hidden"
      style={{ background: cfg.bg, border: `1px solid ${cfg.dot}22` }}
    >
      {/* Card header (always visible) */}
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-start gap-3 p-4 text-left hover:brightness-110 transition-all"
      >
        <Crosshair className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: cfg.dot }} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center flex-wrap gap-2 mb-1">
            <span className={`badge ${cfg.badge}`}>{attack.priority}</span>
            {typeof attack.severity === 'number' && (
              <span className="badge" style={{ background: 'rgba(167,139,250,0.12)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.25)' }}>
                {attack.severity.toFixed(1)} / 10
              </span>
            )}
          </div>
          <h4 className="text-sm font-semibold text-white">{attack.vulnerability_type}</h4>
          <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
            {attack.target_asset}
          </p>
        </div>
        <div className="flex-shrink-0 ml-2 mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
          {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </div>
      </button>

      {/* Expandable body */}
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            key="body"
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.25 }}
            className="overflow-hidden"
          >
            <div className="px-4 pb-4 pt-1 space-y-3">
              {/* Framework tags */}
              <div className="flex flex-wrap gap-2 text-xs">
                <span className="px-2 py-1 rounded-md font-mono" style={{ background: 'rgba(34,211,238,0.08)', color: '#22d3ee', border: '1px solid rgba(34,211,238,0.15)' }}>
                  MAESTRO: {attack.maestro_layer}
                </span>
                <span className="px-2 py-1 rounded-md font-mono" style={{ background: 'rgba(6,214,160,0.08)', color: '#06d6a0', border: '1px solid rgba(6,214,160,0.15)' }}>
                  ATFAA: {attack.atfaa_domain}
                </span>
                <span className="px-2 py-1 rounded-md font-mono" style={{ background: 'rgba(167,139,250,0.08)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.15)' }}>
                  {attack.injection_type}
                </span>
              </div>

              {/* Exploit strategy */}
              <div className="rounded-lg p-3" style={{ background: 'var(--color-bg-surface)' }}>
                <p className="text-xs font-medium mb-1" style={{ color: 'var(--color-text-muted)' }}>Exploit Strategy</p>
                <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>{attack.exploit_strategy}</p>
              </div>

              {/* Adversarial objective */}
              <div className="rounded-lg p-3 flex items-start gap-2"
                   style={{ background: 'rgba(240,192,0,0.06)', border: '1px solid rgba(240,192,0,0.15)' }}>
                <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: '#f0c000' }} />
                <div>
                  <p className="text-xs font-medium mb-0.5" style={{ color: '#f0c000' }}>Adversarial Objective</p>
                  <p className="text-sm" style={{ color: 'var(--color-text-secondary)' }}>{attack.adversarial_objective}</p>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
export default function ResultsDisplay({ results, durationSeconds, mode = 'quick' }: ResultsDisplayProps) {
  const [showJson, setShowJson] = useState(false);

  const downloadJSON = () => {
    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href     = url;
    link.download = `mission_file_${results.agent_id}.json`;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="mt-8 space-y-4"
    >
      {/* Header card */}
      <div className="glass-card p-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4"
           style={{ borderColor: 'var(--color-border-accent)' }}>
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center flex-shrink-0"
               style={{ background: 'linear-gradient(135deg,#06d6a0,#0ea5e9)', boxShadow: '0 4px 16px rgba(6,214,160,0.3)' }}>
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h3 className="text-base font-bold text-white">Analysis Complete</h3>
              <span className={`badge ${mode === 'expert' ? 'badge-expert' : 'badge-quick'}`}>
                {mode === 'expert' ? <Brain className="w-3 h-3" /> : <Zap className="w-3 h-3" />}
                {mode === 'expert' ? 'Expert' : 'Quick'}
              </span>
            </div>
            <div className="flex items-center gap-3 mt-0.5 text-xs" style={{ color: 'var(--color-text-muted)' }}>
              <span>Agent: <span className="font-mono text-white">{results.agent_id}</span></span>
              {typeof durationSeconds === 'number' && (
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {durationSeconds.toFixed(2)}s
                </span>
              )}
            </div>
          </div>
        </div>
        <motion.button
          onClick={downloadJSON}
          whileHover={{ scale: 1.03 }}
          whileTap={{ scale: 0.97 }}
          className="btn-ghost flex-shrink-0"
          style={{ color: 'var(--color-accent-green)', borderColor: 'var(--color-border-accent)' }}
        >
          <Download className="w-4 h-4" />
          Export JSON
        </motion.button>
      </div>

      {/* Risk summary */}
      <div className="glass-card p-5 flex items-start gap-3"
           style={{ borderColor: 'var(--color-border-cyan)' }}>
        <div className="w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0"
             style={{ background: 'rgba(34,211,238,0.1)' }}>
          <Info className="w-4 h-4" style={{ color: 'var(--color-accent-cyan)' }} />
        </div>
        <div>
          <h4 className="text-sm font-semibold text-white mb-1">Risk Summary</h4>
          <p className="text-sm leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
            {results.risk_summary}
          </p>
          <SeveritySummary attacks={results.attack_plan} />
        </div>
      </div>

      {/* Attack plan */}
      <div className="glass-card p-5" style={{ borderColor: 'var(--color-border-accent)' }}>
        <div className="flex items-center gap-2 mb-4">
          <div className="w-8 h-8 rounded-lg flex items-center justify-center"
               style={{ background: 'rgba(6,214,160,0.1)' }}>
            <Target className="w-4 h-4" style={{ color: 'var(--color-accent-green)' }} />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">Attack Plan</h3>
            <p className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
              {results.attack_plan.length} vulnerabilities identified
            </p>
          </div>
        </div>

        <div className="space-y-2">
          {results.attack_plan.map((attack, i) => (
            <AttackCard key={i} attack={attack} index={i} />
          ))}
        </div>
      </div>

      {/* JSON toggle */}
      <div className="glass-card overflow-hidden">
        <button
          onClick={() => setShowJson((s) => !s)}
          className="w-full flex items-center justify-between px-5 py-3 text-sm font-medium transition-colors hover:brightness-110"
          style={{ color: 'var(--color-text-secondary)' }}
        >
          <span>Raw JSON Output</span>
          {showJson ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </button>

        <AnimatePresence>
          {showJson && (
            <motion.div
              key="json"
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.3 }}
              className="overflow-hidden"
            >
              <div className="max-h-80 overflow-auto border-t" style={{ borderColor: 'var(--color-border)' }}>
                <SyntaxHighlighter
                  language="json"
                  style={vscDarkPlus}
                  customStyle={{ margin: 0, background: 'transparent', fontSize: '0.8rem' }}
                >
                  {JSON.stringify(results, null, 2)}
                </SyntaxHighlighter>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
