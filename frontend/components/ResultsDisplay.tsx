'use client';

import { useEffect, useRef, useState } from 'react';
import { MissionFile, type AnalysisMode, type EvaluateResponse } from '@/types';
import { payloadApi, evaluationApi } from '@/lib/api';
import EvaluationDisplay from '@/components/EvaluationDisplay';

interface ResultsDisplayProps {
  results: MissionFile;
  durationSeconds?: number;
  mode?: AnalysisMode;
  agentDescription?: string;
  token?: string;
  onStageChange?: (stage: 'payloads' | 'simulation' | 'done') => void;
}

export default function ResultsDisplay({
  results,
  agentDescription = '',
  token = '',
  mode,
  durationSeconds,
  onStageChange,
}: ResultsDisplayProps) {
  const [evalData, setEvalData] = useState<EvaluateResponse | null>(null);
  const [simError, setSimError] = useState('');
  // Guard against React 18 StrictMode double-mount firing the pipeline twice
  const hasRun = useRef(false);

  useEffect(() => {
    if (!token || !agentDescription) return;
    if (hasRun.current) return;
    hasRun.current = true;

    const run = async () => {
      onStageChange?.('payloads');
      setSimError('');
      let payloads;
      try {
        const data = await payloadApi.generate(token, agentDescription, results);
        payloads = data.payloads;
      } catch (err) {
        setSimError(err instanceof Error ? err.message : 'Payload generation failed.');
        return;
      }

      onStageChange?.('simulation');
      try {
        const data = await evaluationApi.evaluate(token, payloads);
        setEvalData(data);
        onStageChange?.('done');
      } catch (err) {
        setSimError(err instanceof Error ? err.message : 'Simulation failed.');
      }
    };

    run();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="mt-2 space-y-4">
      {simError && (
        <div className="rounded-xl p-4 text-sm"
             style={{ background: 'rgba(248,81,73,0.08)', border: '1px solid rgba(248,81,73,0.25)', color: '#fca5a5' }}>
          {simError}
        </div>
      )}
      {evalData && (
        <EvaluationDisplay
          data={evalData}
          missionFile={results}
          agentDescription={agentDescription}
          mode={mode}
          durationSeconds={durationSeconds}
          token={token}
        />
      )}
    </div>
  );
}
