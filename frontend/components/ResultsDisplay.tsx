'use client';

import { useEffect, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import { Loader2, ShieldAlert, ShieldCheck, Skull } from 'lucide-react';
import {
  MissionFile,
  type AnalysisMode,
  type EvaluateResponse,
  type AttackObjective,
  type PayloadResult,
  type SystemInfo,
} from '@/types';
import { payloadApi, evaluationApi, systemApi } from '@/lib/api';
import EvaluationDisplay from '@/components/EvaluationDisplay';

interface ResultsDisplayProps {
  results: MissionFile;
  durationSeconds?: number;
  mode?: AnalysisMode;
  agentDescription?: string;
  token?: string;
  // Victim wiring + attack strength (Quick mode form fields)
  victimUrl?: string;
  victimModel?: string;
  maxPayloadsPerVuln?: number;
  // Pre-computed pipeline outputs (set by the adaptive red-team loop)
  precomputedPayloads?: PayloadResult[];
  precomputedEval?: EvaluateResponse;
  onStageChange?: (stage: 'payloads' | 'simulation' | 'done') => void;
}

type Stage = 'analyzed' | 'generating-payloads' | 'simulating' | 'done' | 'error';

// ---------------------------------------------------------------------------
// Visual helpers
// ---------------------------------------------------------------------------

function priorityColor(p: string): string {
  switch (p.toUpperCase()) {
    case 'CRITICAL': return '#f85149';
    case 'HIGH':     return '#fb923c';
    case 'MEDIUM':   return '#f0a500';
    default:         return '#64748b';
  }
}

function priorityIcon(p: string) {
  const c = priorityColor(p);
  switch (p.toUpperCase()) {
    case 'CRITICAL': return <Skull        size={14} color={c} />;
    case 'HIGH':     return <ShieldAlert  size={14} color={c} />;
    default:         return <ShieldCheck  size={14} color={c} />;
  }
}

// ---------------------------------------------------------------------------
// Single attack-objective card
// ---------------------------------------------------------------------------

function ObjectiveCard({ obj }: { obj: AttackObjective }) {
  const color = priorityColor(obj.priority);
  return (
    <div
      className="rounded-xl p-4"
      style={{ background: 'rgba(255,255,255,0.02)', border: `1px solid ${color}33` }}
    >
      <div className="flex items-start justify-between gap-2 mb-2">
        <h4 className="text-sm font-semibold text-white">{obj.vulnerability_type}</h4>
        <span
          className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-full"
          style={{ background: `${color}1f`, color }}
        >
          {priorityIcon(obj.priority)}
          {obj.priority}
          {typeof obj.severity === 'number' && obj.severity > 0
            ? ` · ${obj.severity.toFixed(1)}`
            : ''}
        </span>
      </div>

      <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs mb-2"
           style={{ color: 'var(--color-text-muted)' }}>
        <div><span className="font-semibold">MAESTRO:</span> {obj.maestro_layer}</div>
        <div><span className="font-semibold">ATFAA:</span> {obj.atfaa_domain}</div>
        <div className="col-span-2">
          <span className="font-semibold">Injection:</span> {obj.injection_type}
        </div>
        <div className="col-span-2">
          <span className="font-semibold">Target:</span> {obj.target_asset}
        </div>
      </div>

      <p className="text-xs leading-relaxed mb-1" style={{ color: 'var(--color-text-secondary)' }}>
        <span className="font-semibold text-white">Strategy:</span> {obj.exploit_strategy}
      </p>
      <p className="text-xs leading-relaxed" style={{ color: 'var(--color-text-secondary)' }}>
        <span className="font-semibold text-white">Goal:</span> {obj.adversarial_objective}
      </p>
      {obj.required_camouflage && obj.required_camouflage.toUpperCase() !== 'NONE' && (
        <p className="text-xs leading-relaxed mt-2 italic"
           style={{ color: '#a78bfa' }}>
          <span className="font-semibold">Camouflage:</span> {obj.required_camouflage}
        </p>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Pipeline stage indicator
// ---------------------------------------------------------------------------

function StageBanner({ stage, error }: { stage: Stage; error: string }) {
  if (stage === 'analyzed') return null;
  if (stage === 'error') {
    return (
      <div
        className="rounded-xl p-4 text-sm"
        style={{
          background: 'rgba(248,81,73,0.08)',
          border:    '1px solid rgba(248,81,73,0.25)',
          color:     '#fca5a5',
        }}
      >
        Pipeline stopped: {error}
      </div>
    );
  }
  const label = stage === 'generating-payloads'
    ? 'Generating adversarial payloads with the redteam model…'
    : stage === 'simulating'
    ? 'Sending payloads to the victim agent and evaluating responses…'
    : 'Pipeline complete.';
  return (
    <div
      className="rounded-xl p-4 flex items-center gap-3 text-sm"
      style={{
        background: 'rgba(6,214,160,0.06)',
        border:    '1px solid rgba(6,214,160,0.25)',
        color:     '#a7f3d0',
      }}
    >
      {stage !== 'done' && <Loader2 className="w-4 h-4 animate-spin" />}
      {label}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function ResultsDisplay({
  results,
  agentDescription = '',
  token = '',
  mode,
  durationSeconds,
  victimUrl,
  victimModel,
  maxPayloadsPerVuln,
  precomputedPayloads,
  precomputedEval,
  onStageChange,
}: ResultsDisplayProps) {
  const [evalData, setEvalData]     = useState<EvaluateResponse | null>(precomputedEval ?? null);
  const [payloads, setPayloads]     = useState<PayloadResult[] | null>(precomputedPayloads ?? null);
  const [systemInfo, setSystemInfo] = useState<SystemInfo | null>(null);
  const [stage, setStage]           = useState<Stage>(precomputedEval ? 'done' : 'analyzed');
  const [simError, setSimError]     = useState('');

  // Guard against React 18 StrictMode double-mount firing the pipeline twice
  const hasRun = useRef(false);

  useEffect(() => {
    // Skip the pipeline entirely if results were already computed (loop mode)
    if (precomputedEval) {
      systemApi.info().then(setSystemInfo).catch(() => {});
      return;
    }
    if (!token || !agentDescription) return;
    if (hasRun.current) return;
    hasRun.current = true;

    (async () => {
      // Snapshot the actual model wiring at scan time — used by the JSON
      // export so a reviewer can verify which analyzer/generator/victim
      // produced this report.
      systemApi.info().then(setSystemInfo).catch(() => { /* non-fatal */ });

      // ── Stage 1: payload generation ──────────────────────────────────────
      setStage('generating-payloads');
      onStageChange?.('payloads');
      let generated: PayloadResult[];
      try {
        const data = await payloadApi.generate(
          token, agentDescription, results, maxPayloadsPerVuln, victimUrl,
        );
        generated  = data.payloads;
        setPayloads(generated);
      } catch (err) {
        setSimError(err instanceof Error ? err.message : 'Payload generation failed.');
        setStage('error');
        return;
      }

      // ── Stage 2: attack simulation ──────────────────────────────────────
      setStage('simulating');
      onStageChange?.('simulation');
      try {
        const data = await evaluationApi.evaluate(token, generated, {
          victim_url:            victimUrl   || undefined,
          victim_model:          victimModel || undefined,
          max_payloads_per_vuln: maxPayloadsPerVuln,
        });
        setEvalData(data);
        setStage('done');
        onStageChange?.('done');
      } catch (err) {
        setSimError(err instanceof Error ? err.message : 'Simulation failed.');
        setStage('error');
      }
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const { agent_id, risk_summary, attack_plan, allowed_scope, scope_lock_strength } = results;
  const lockShown = scope_lock_strength && scope_lock_strength !== 'NONE';

  return (
    <div className="mt-4 space-y-4">
      {/* Attack plan — visible immediately when analysis returns */}
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="glass-card p-6"
      >
        <div className="flex items-start justify-between mb-4 gap-4">
          <div>
            <h3 className="text-lg font-bold text-white">Attack Plan</h3>
            <p className="text-xs mt-0.5" style={{ color: 'var(--color-text-muted)' }}>
              Agent ID: <span className="font-mono">{agent_id}</span>
              {durationSeconds !== undefined && (
                <> · Analysis took {durationSeconds.toFixed(1)}s</>
              )}
              {' · '}{attack_plan.length} vulnerabilities identified
            </p>
          </div>
        </div>

        <p className="text-sm leading-relaxed mb-3"
           style={{ color: 'var(--color-text-secondary)' }}>
          {risk_summary}
        </p>

        {lockShown && (
          <div className="rounded-lg p-3 mb-4 text-xs flex flex-wrap gap-x-4 gap-y-1"
               style={{ background: 'rgba(167,139,250,0.08)', border: '1px solid rgba(167,139,250,0.30)', color: '#c4b5fd' }}>
            <span><span className="font-semibold">Scope lock:</span> {scope_lock_strength}</span>
            {allowed_scope && (
              <span><span className="font-semibold">Allowed scope:</span> {allowed_scope}</span>
            )}
            <span className="opacity-80">
              Payloads will be camouflaged inside this scope so the agent engages with the technique.
            </span>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {attack_plan.map((obj, i) => (
            <ObjectiveCard key={i} obj={obj} />
          ))}
        </div>
      </motion.div>

      {/* Pipeline progress / error banner */}
      <StageBanner stage={stage} error={simError} />

      {/* Final evaluation results */}
      {evalData && (
        <EvaluationDisplay
          data={evalData}
          missionFile={results}
          agentDescription={agentDescription}
          mode={mode}
          durationSeconds={durationSeconds}
          token={token}
          payloads={payloads ?? undefined}
          systemInfo={systemInfo ?? undefined}
        />
      )}
    </div>
  );
}
