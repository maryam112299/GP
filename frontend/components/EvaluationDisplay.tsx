'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import type { EvaluateResponse, MissionFile, AnalysisMode, VulnEvalSummary } from '@/types';
import { reportApi } from '@/lib/api';

// ---------------------------------------------------------------------------
// Risk label helpers
// ---------------------------------------------------------------------------
function riskLabel(score: number): string {
  if (score === 0)    return 'SAFE';
  if (score < 0.34)  return 'LOW RISK';
  if (score < 0.67)  return 'MEDIUM RISK';
  return 'HIGH RISK';
}

function riskColor(score: number): string {
  if (score === 0)    return '#3fb950';  // green
  if (score < 0.34)  return '#3fb950';  // green
  if (score < 0.67)  return '#f0a500';  // amber
  return '#f85149';                      // red
}

function riskBg(score: number): string {
  if (score === 0)    return 'rgba(63,185,80,0.08)';
  if (score < 0.34)  return 'rgba(63,185,80,0.08)';
  if (score < 0.67)  return 'rgba(240,165,0,0.08)';
  return 'rgba(248,81,73,0.08)';
}

// ---------------------------------------------------------------------------
// Overall risk gauge (SVG ring)
// ---------------------------------------------------------------------------
function RiskGauge({ score }: { score: number }) {
  const r       = 52;
  const circ    = 2 * Math.PI * r;
  const filled  = circ * score;
  const color   = riskColor(score);
  const label   = riskLabel(score);
  const pct     = Math.round(score * 100);

  return (
    <div className="flex flex-col items-center gap-3">
      <svg width="128" height="128" viewBox="0 0 128 128">
        {/* Track */}
        <circle cx="64" cy="64" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="12" />
        {/* Fill */}
        <circle
          cx="64" cy="64" r={r}
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeDasharray={`${filled} ${circ}`}
          strokeLinecap="round"
          transform="rotate(-90 64 64)"
          style={{ transition: 'stroke-dasharray 0.6s ease' }}
        />
        {/* Percentage text */}
        <text x="64" y="60" textAnchor="middle" fill="white" fontSize="22" fontWeight="700">
          {pct}%
        </text>
        <text x="64" y="78" textAnchor="middle" fill={color} fontSize="9" fontWeight="600" letterSpacing="0.08em">
          RISK
        </text>
      </svg>
      <span className="text-sm font-bold tracking-wide" style={{ color }}>{label}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Per-vulnerability row
// ---------------------------------------------------------------------------
function VulnRow({ item }: { item: VulnEvalSummary }) {
  const color  = riskColor(item.risk_score);
  const pct    = Math.round(item.risk_score * 100);
  const label  = riskLabel(item.risk_score);

  return (
    <div
      className="rounded-xl p-4"
      style={{ background: riskBg(item.risk_score), border: `1px solid ${color}22` }}
    >
      {/* Header */}
      <div className="flex items-start justify-between gap-2 mb-3">
        <div className="min-w-0">
          <p className="text-sm font-semibold text-white truncate">{item.vulnerability_type}</p>
          <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--color-text-muted)' }}>
            {item.target_asset}
          </p>
        </div>
        <span
          className="flex-shrink-0 text-xs font-bold px-2 py-0.5 rounded-full"
          style={{ background: `${color}22`, color }}
        >
          {label}
        </span>
      </div>

      {/* Risk bar */}
      <div className="mb-3">
        <div className="flex justify-between text-xs mb-1" style={{ color: 'var(--color-text-muted)' }}>
          <span>Risk score</span>
          <span style={{ color }}>{pct}%</span>
        </div>
        <div className="h-1.5 rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{ width: `${pct}%`, background: color }}
          />
        </div>
      </div>

      {/* Counts */}
      <div className="flex gap-3 text-xs">
        <span style={{ color: '#3fb950' }}>✓ {item.success_count} safe</span>
        <span style={{ color: '#f85149' }}>✗ {item.fail_count} vuln</span>
        {item.unknown_count > 0 && (
          <span style={{ color: '#94a3b8' }}>? {item.unknown_count} unknown</span>
        )}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Download button
// ---------------------------------------------------------------------------
interface DownloadButtonProps {
  data: EvaluateResponse;
  missionFile?: MissionFile;
  agentDescription?: string;
  mode?: AnalysisMode;
  durationSeconds?: number;
  token?: string;
}

function DownloadReportButton({
  data,
  missionFile,
  agentDescription = '',
  mode = 'quick',
  durationSeconds = 0,
  token = '',
}: DownloadButtonProps) {
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState('');

  async function handleDownload() {
    if (!token || !missionFile) return;
    setLoading(true);
    setError('');
    try {
      const blob = await reportApi.generate(token, {
        analysis:         missionFile,
        evaluation:       data,
        mode,
        agent_description: agentDescription,
        duration_seconds:  durationSeconds,
      });

      // Trigger browser download via temporary object URL
      const url  = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href     = url;
      link.download = `llmtron_report_${missionFile.agent_id}.pdf`;
      link.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Report generation failed.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <button
        onClick={handleDownload}
        disabled={loading || !token || !missionFile}
        className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold transition-all"
        style={{
          background: loading ? 'rgba(6,214,160,0.15)' : 'rgba(6,214,160,0.12)',
          border:     '1px solid rgba(6,214,160,0.35)',
          color:      loading ? 'rgba(6,214,160,0.6)' : '#06d6a0',
          cursor:     loading ? 'not-allowed' : 'pointer',
        }}
      >
        {loading ? (
          <>
            <svg className="animate-spin" width="14" height="14" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" strokeWidth="2.5">
              <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
            </svg>
            Generating…
          </>
        ) : (
          <>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
                 stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>
              <polyline points="7 10 12 15 17 10"/>
              <line x1="12" y1="15" x2="12" y2="3"/>
            </svg>
            Download Report
          </>
        )}
      </button>
      {error && (
        <p className="mt-1.5 text-xs" style={{ color: '#f85149' }}>{error}</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------
interface Props {
  data: EvaluateResponse;
  // Optional — needed for PDF report download
  missionFile?: MissionFile;
  agentDescription?: string;
  mode?: AnalysisMode;
  durationSeconds?: number;
  token?: string;
}

export default function EvaluationDisplay({
  data,
  missionFile,
  agentDescription,
  mode,
  durationSeconds,
  token,
}: Props) {
  const {
    vuln_summaries,
    overall_risk_score,
    total_tested,
    total_success,
    total_fail,
    total_unknown,
  } = data;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="glass-card p-6 mt-4"
    >
      {/* Title row + download button */}
      <div className="flex items-center justify-between mb-5">
        <h3 className="text-lg font-bold text-white">Attack Simulation Results</h3>
        {missionFile && token && (
          <DownloadReportButton
            data={data}
            missionFile={missionFile}
            agentDescription={agentDescription}
            mode={mode}
            durationSeconds={durationSeconds}
            token={token}
          />
        )}
      </div>

      {/* Overall gauge + stats */}
      <div className="flex flex-col sm:flex-row items-center gap-6 mb-6 pb-6"
           style={{ borderBottom: '1px solid var(--color-border)' }}>
        <RiskGauge score={overall_risk_score} />

        <div className="flex-1 grid grid-cols-3 gap-3 w-full">
          {[
            { label: 'Tested',      value: total_tested,  color: 'var(--color-text-secondary)' },
            { label: 'Refused',     value: total_success, color: '#3fb950' },
            { label: 'Complied',    value: total_fail,    color: '#f85149' },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="rounded-xl p-3 text-center"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--color-border)' }}
            >
              <p className="text-2xl font-bold" style={{ color }}>{value}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>{label}</p>
            </div>
          ))}
          {total_unknown > 0 && (
            <div
              className="rounded-xl p-3 text-center col-span-3 sm:col-span-1"
              style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid var(--color-border)' }}
            >
              <p className="text-2xl font-bold" style={{ color: '#94a3b8' }}>{total_unknown}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>Unknown</p>
            </div>
          )}
        </div>
      </div>

      {/* Per-vulnerability breakdown */}
      <div className="space-y-3">
        <h4 className="text-sm font-semibold" style={{ color: 'var(--color-text-secondary)' }}>
          Vulnerability Breakdown
        </h4>
        {vuln_summaries
          .filter((v) => v.total > 0)
          .sort((a, b) => b.risk_score - a.risk_score)
          .map((item) => (
            <VulnRow key={item.vulnerability_type} item={item} />
          ))}
      </div>
    </motion.div>
  );
}
