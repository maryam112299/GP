'use client';

interface AnalyzingPanelProps {
  usesMcp?: boolean;
  usesRag?: boolean;
}

export default function AnalyzingPanel({ usesMcp, usesRag }: AnalyzingPanelProps) {
  type Step = { label: string; state: 'done' | 'active' | 'pending' };

  const steps: Step[] = [
    { label: 'MAESTRO layer analysis',     state: 'done' },
    { label: 'ATFAA domain mapping',       state: 'done' },
    ...(usesMcp ? [{ label: 'MCP attack surface mapping…', state: 'active' as const }] : []),
    ...(usesRag ? [{ label: 'RAG attack surface mapping…', state: 'active' as const }] : []),
    { label: 'Generating risk score',      state: 'pending' },
  ];

  return (
    <div style={{
      background: '#fff', border: '1px solid var(--color-border)',
      borderRadius: 16, padding: 40,
      display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
      minHeight: 420, animation: 'fadeUp .4s ease',
    }}>
      {/* Spinner */}
      <div style={{
        width: 44, height: 44, borderRadius: '50%',
        border: '3px solid #e0e7ff',
        borderTopColor: 'var(--color-accent)',
        animation: 'spin .8s linear infinite',
      }} />

      <div style={{ fontSize: 17, fontWeight: 600, color: 'var(--color-text-primary)', marginTop: 22 }}>
        Running security analysis…
      </div>
      <div style={{ fontSize: 13, color: '#64748b', marginTop: 6 }}>
        Mapping attack surface across MAESTRO layers
      </div>

      {/* Checklist */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 9, marginTop: 26, width: '100%', maxWidth: 320 }}>
        {steps.map((step, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {step.state === 'done' && (
              <div style={{
                width: 18, height: 18, borderRadius: '50%',
                background: '#dcfce7', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#16a34a" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              </div>
            )}
            {step.state === 'active' && (
              <div style={{
                width: 18, height: 18, borderRadius: '50%',
                border: '2px solid var(--color-accent)',
                display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
              }}>
                <div style={{ width: 7, height: 7, borderRadius: '50%', background: 'var(--color-accent)' }} />
              </div>
            )}
            {step.state === 'pending' && (
              <div style={{
                width: 18, height: 18, borderRadius: '50%',
                border: '2px solid #e2e8f0', flexShrink: 0,
              }} />
            )}
            <span style={{
              fontSize: 13,
              color: step.state === 'done' ? '#16a34a' : step.state === 'active' ? 'var(--color-accent)' : '#94a3b8',
              fontWeight: step.state === 'pending' ? 400 : 500,
              animation: step.state === 'active' ? 'barpulse 1.2s ease-in-out infinite' : undefined,
            }}>
              {step.label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
