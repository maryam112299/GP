'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { ChevronDown, ChevronRight, FileJson } from 'lucide-react';
import type {
  EvaluateResponse,
  MissionFile,
  AnalysisMode,
  VulnEvalSummary,
  PayloadResult,
  PayloadEvalResult,
  SystemInfo,
} from '@/types';
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
  if (score === 0)    return '#16a34a';  // green
  if (score < 0.34)  return '#16a34a';  // green
  if (score < 0.67)  return '#f0a500';  // amber
  return '#dc2626';                      // red
}

function riskBg(score: number): string {
  if (score === 0)    return 'var(--color-success-bg)';
  if (score < 0.34)  return 'var(--color-success-bg)';
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
        <circle cx="64" cy="64" r={r} fill="none" stroke="#e5e7eb" strokeWidth="12" />
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
        <text x="64" y="60" textAnchor="middle" fill="#0f172a" fontSize="22" fontWeight="700">
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
function verdictColor(result: string): string {
  if (result === 'SUCCESS') return '#16a34a';
  if (result === 'FAIL')    return '#dc2626';
  return '#94a3b8';
}

function verdictLabel(result: string): string {
  if (result === 'SUCCESS') return 'REFUSED';
  if (result === 'FAIL')    return 'COMPLIED';
  return 'UNKNOWN';
}

function EvidenceList({ items }: { items: NonNullable<PayloadEvalResult['evidence']> }) {
  return (
    <div>
      <p className="text-[10px] uppercase font-semibold mb-1"
         style={{ color: 'var(--color-critical)' }}>Evidence ({items.length})</p>
      <ul className="space-y-1 text-[11px]">
        {items.map((ev, i) => {
          const rest = Object.fromEntries(Object.entries(ev).filter(([k]) => k !== 'kind'));
          return (
            <li key={i} className="rounded p-2"
                style={{ background: 'var(--color-critical-bg)', border: '1px solid rgba(248,81,73,0.25)' }}>
              <div className="font-mono font-semibold" style={{ color: 'var(--color-critical)' }}>
                {String(ev.kind || 'finding')}
              </div>
              {Object.entries(rest).map(([k, v]) => (
                <div key={k} className="font-mono"
                     style={{ color: '#475569', wordBreak: 'break-word' }}>
                  <span style={{ color: 'var(--color-text-muted)' }}>{k}:</span>{' '}
                  {typeof v === 'string' ? v : JSON.stringify(v)}
                </div>
              ))}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function PayloadAttemptCard({ pr }: { pr: PayloadEvalResult }) {
  const c = verdictColor(pr.result);
  const hasEvidence = (pr.evidence?.length ?? 0) > 0;
  return (
    <div
      className="rounded-lg p-3 text-xs space-y-2"
      style={{ background: '#f8fafc', border: `1px solid ${c}22` }}
    >
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <span className="font-bold px-1.5 py-0.5 rounded"
              style={{ background: `${c}22`, color: c, fontSize: '10px', letterSpacing: '.04em' }}>
          {verdictLabel(pr.result)} · {pr.eval_method}
        </span>
        <span className="text-[10px] uppercase tracking-wide"
              style={{ color: 'var(--color-text-muted)' }}>
          source: {pr.payload_type}
        </span>
      </div>
      {hasEvidence && <EvidenceList items={pr.evidence!} />}
      <div>
        <p className="text-[10px] uppercase font-semibold mb-1"
           style={{ color: 'var(--color-text-muted)' }}>Payload sent</p>
        <pre className="whitespace-pre-wrap font-mono leading-snug p-2 rounded"
             style={{ background: '#0f172a', color: '#f1f5f9', wordBreak: 'break-word' }}>
{pr.payload}
        </pre>
      </div>
      <div>
        <p className="text-[10px] uppercase font-semibold mb-1"
           style={{ color: 'var(--color-text-muted)' }}>Victim response</p>
        <pre className="whitespace-pre-wrap font-mono leading-snug p-2 rounded"
             style={{ background: '#0f172a', color: '#475569', wordBreak: 'break-word' }}>
{pr.victim_response || '(empty)'}
        </pre>
      </div>
    </div>
  );
}

function VulnRow({ item }: { item: VulnEvalSummary }) {
  const [open, setOpen] = useState(false);
  const color  = riskColor(item.risk_score);
  const pct    = Math.round(item.risk_score * 100);
  const label  = riskLabel(item.risk_score);
  const hasDetails = (item.payload_results?.length ?? 0) > 0;

  return (
    <div
      className="rounded-xl p-4"
      style={{ background: riskBg(item.risk_score), border: `1px solid ${color}22` }}
    >
      {/* Header — clickable to expand */}
      <button
        type="button"
        onClick={() => hasDetails && setOpen((v) => !v)}
        className="w-full text-left"
        style={{ cursor: hasDetails ? 'pointer' : 'default' }}
      >
        <div className="flex items-start justify-between gap-2 mb-3">
          <div className="min-w-0 flex items-start gap-2">
            {hasDetails && (
              open
                ? <ChevronDown  size={14} className="mt-0.5" style={{ color: 'var(--color-text-muted)' }} />
                : <ChevronRight size={14} className="mt-0.5" style={{ color: 'var(--color-text-muted)' }} />
            )}
            <div className="min-w-0">
              <p className="text-sm font-semibold truncate" style={{ color: 'var(--color-text-primary)' }}>{item.vulnerability_type}</p>
              <p className="text-xs mt-0.5 truncate" style={{ color: 'var(--color-text-muted)' }}>
                {item.target_asset}
              </p>
            </div>
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
          <div className="h-1.5 rounded-full" style={{ background: 'var(--color-border)' }}>
            <div
              className="h-full rounded-full transition-all duration-500"
              style={{ width: `${pct}%`, background: color }}
            />
          </div>
        </div>

        {/* Counts */}
        <div className="flex gap-3 text-xs">
          <span style={{ color: 'var(--color-success)' }}>✓ {item.success_count} refused</span>
          <span style={{ color: 'var(--color-critical)' }}>✗ {item.fail_count} complied</span>
          {item.unknown_count > 0 && (
            <span style={{ color: '#94a3b8' }}>? {item.unknown_count} unknown</span>
          )}
          {hasDetails && (
            <span className="ml-auto" style={{ color: 'var(--color-text-muted)' }}>
              {open ? 'Hide attempts' : `View ${item.payload_results.length} attempts`}
            </span>
          )}
        </div>
      </button>

      {/* Expanded payload list */}
      {open && hasDetails && (
        <div className="mt-3 pt-3 space-y-2"
             style={{ borderTop: `1px dashed ${color}33` }}>
          {item.payload_results.map((pr, i) => (
            <PayloadAttemptCard key={i} pr={pr} />
          ))}
        </div>
      )}
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
          background: 'var(--color-accent-soft)',
          border:     '1px solid var(--color-border-accent)',
          color:      loading ? '#94a3b8' : 'var(--color-accent)',
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
        <p className="mt-1.5 text-xs" style={{ color: 'var(--color-critical)' }}>{error}</p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Attack-package JSON download (raw audit trail)
// ---------------------------------------------------------------------------

interface PackageProps {
  data:             EvaluateResponse;
  missionFile:      MissionFile;
  agentDescription: string;
  mode:             AnalysisMode;
  durationSeconds:  number;
  payloads?:        PayloadResult[];
  systemInfo?:      SystemInfo;
}

function DownloadPackageButton({
  data,
  missionFile,
  agentDescription,
  mode,
  durationSeconds,
  payloads,
  systemInfo,
}: PackageProps) {
  function buildPackage() {
    // Flat per-variant payload list, mirroring the audit format the user shared.
    const flatPayloads: Array<Record<string, unknown>> = [];
    let applicable = 0;
    let notApplicable = 0;
    (payloads ?? []).forEach((p) => {
      if (p.applicable) applicable += 1; else notApplicable += 1;
      p.payloads.forEach((text, i) =>
        flatPayloads.push({
          vulnerability_type: p.vulnerability_type,
          target_asset:       p.target_asset,
          source:             'specific',
          variant:            i + 1,
          payload:            text,
        }),
      );
      p.generic_payloads.forEach((text, i) =>
        flatPayloads.push({
          vulnerability_type: p.vulnerability_type,
          target_asset:       p.target_asset,
          source:             'generic',
          variant:            i + 1,
          payload:            text,
        }),
      );
    });

    return {
      generated_at:        new Date().toISOString(),
      mode,
      target_description:  agentDescription,
      duration_seconds:    durationSeconds,
      analyzer_model:      systemInfo?.analyzer_model  ?? null,
      generator_model:     systemInfo?.generator_model ?? null,
      victim_model:        systemInfo?.victim_model    ?? null,
      victim_url:          systemInfo?.victim_url      ?? null,
      evaluator_model:     systemInfo?.evaluator_model ?? null,
      scoring_mode:        systemInfo?.scoring_mode    ?? null,
      analysis:            missionFile,
      payloads:            flatPayloads,
      applicable_count:    applicable,
      not_applicable_count: notApplicable,
      evaluation:          data,
    };
  }

  function handleDownload() {
    const json = JSON.stringify(buildPackage(), null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `attack_package_${missionFile.agent_id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  return (
    <button
      onClick={handleDownload}
      className="flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-semibold transition-all"
      style={{
        background: 'rgba(56,189,248,0.10)',
        border:     '1px solid rgba(56,189,248,0.35)',
        color:      '#38bdf8',
      }}
    >
      <FileJson size={14} />
      Download JSON
    </button>
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
  // Optional — needed for the raw-audit JSON export
  payloads?: PayloadResult[];
  systemInfo?: SystemInfo;
}

export default function EvaluationDisplay({
  data,
  missionFile,
  agentDescription,
  mode,
  durationSeconds,
  token,
  payloads,
  systemInfo,
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
      className="card p-6 mt-4"
    >
      {/* Title row + download buttons */}
      <div className="flex items-center justify-between mb-3 flex-wrap gap-3">
        <h3 className="text-lg font-bold" style={{ color: 'var(--color-text-primary)' }}>Attack Simulation Results</h3>
        <div className="flex items-center gap-2 flex-wrap">
          {missionFile && (
            <DownloadPackageButton
              data={data}
              missionFile={missionFile}
              agentDescription={agentDescription ?? ''}
              mode={mode ?? 'quick'}
              durationSeconds={durationSeconds ?? 0}
              payloads={payloads}
              systemInfo={systemInfo}
            />
          )}
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
      </div>

      {/* Model attribution strip — proves which models drove this scan */}
      {systemInfo && (
        <div className="mb-5 text-xs flex flex-wrap gap-x-4 gap-y-1"
             style={{ color: 'var(--color-text-muted)' }}>
          <span><span className="font-semibold">Analyzer:</span> {systemInfo.analyzer_model}</span>
          <span><span className="font-semibold">Generator:</span> {systemInfo.generator_model}</span>
          <span><span className="font-semibold">Victim:</span> {systemInfo.victim_model} @ {systemInfo.victim_url}</span>
        </div>
      )}

      {/* Overall gauge + stats */}
      <div className="flex flex-col sm:flex-row items-center gap-6 mb-6 pb-6"
           style={{ borderBottom: '1px solid var(--color-border)' }}>
        <RiskGauge score={overall_risk_score} />

        <div className="flex-1 grid grid-cols-3 gap-3 w-full">
          {[
            { label: 'Tested',      value: total_tested,  color: 'var(--color-text-secondary)' },
            { label: 'Refused',     value: total_success, color: 'var(--color-success)' },
            { label: 'Complied',    value: total_fail,    color: 'var(--color-critical)' },
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="rounded-xl p-3 text-center"
              style={{ background: 'var(--color-bg-base)', border: '1px solid var(--color-border)' }}
            >
              <p className="text-2xl font-bold" style={{ color }}>{value}</p>
              <p className="text-xs mt-1" style={{ color: 'var(--color-text-muted)' }}>{label}</p>
            </div>
          ))}
          {total_unknown > 0 && (
            <div
              className="rounded-xl p-3 text-center col-span-3 sm:col-span-1"
              style={{ background: 'var(--color-bg-base)', border: '1px solid var(--color-border)' }}
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
