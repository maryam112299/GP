'use client';

import { useEffect, useState } from 'react';
import { scansApi } from '@/lib/api';
import type { ScanRecord } from '@/types';

interface DashboardProps {
  token: string;
}

function riskScore(scan: ScanRecord): number {
  const plan = scan.output?.attack_plan ?? [];
  if (!plan.length) return 0;
  const crit = plan.filter(o => o.priority === 'CRITICAL').length;
  const high = plan.filter(o => o.priority === 'HIGH').length;
  return Math.min(100, Math.round((crit * 25 + high * 10) / Math.max(plan.length, 1)));
}

function hasCritical(scan: ScanRecord): boolean {
  return (scan.output?.attack_plan ?? []).some(o => o.priority === 'CRITICAL');
}

function agentName(scan: ScanRecord): string {
  return scan.output?.agent_id || 'Unknown Agent';
}

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
}

export default function Dashboard({ token }: DashboardProps) {
  const [scans, setScans] = useState<ScanRecord[]>([]);

  useEffect(() => {
    if (!token) return;
    scansApi.getAll(token).then(r => setScans(r.scans)).catch(() => {});
  }, [token]);

  const totalScans   = scans.length;
  const openCrit     = scans.filter(hasCritical).length;
  const avgRisk      = totalScans
    ? Math.round(scans.reduce((acc, s) => acc + riskScore(s), 0) / totalScans)
    : 0;
  const agentsTested = new Set(scans.map(agentName)).size;

  const statCard = (
    label: string,
    value: number | string,
    valueColor = 'var(--color-text-primary)',
    borderColor = 'var(--color-border)',
  ) => (
    <div style={{
      background: '#fff',
      border: `1px solid ${borderColor}`,
      borderRadius: 14,
      padding: 20,
    }}>
      <div style={{ fontSize: 13, color: '#64748b' }}>{label}</div>
      <div style={{ fontSize: 32, fontWeight: 700, color: valueColor, marginTop: 6 }}>{value}</div>
    </div>
  );

  return (
    <div style={{ padding: '28px 32px', animation: 'fadeUp .35s ease' }}>
      <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-text-primary)' }}>Dashboard</div>
      <div style={{ fontSize: 14, color: '#64748b', marginTop: 4 }}>
        Overview across all of your security scans.
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 16, marginTop: 24 }}>
        {statCard('Total Scans',    totalScans)}
        {statCard('Open Critical',  openCrit,  'var(--color-critical)', 'var(--color-critical-bd)')}
        {statCard('Avg Risk Score', avgRisk,   'var(--color-risk-high)')}
        {statCard('Agents Tested',  agentsTested)}
      </div>

      {/* Recent scans table */}
      {scans.length > 0 && (
        <div style={{
          background: '#fff',
          border: '1px solid var(--color-border)',
          borderRadius: 14,
          overflow: 'hidden',
          marginTop: 16,
        }}>
          <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--color-bg-base)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--color-text-primary)' }}>Recent Scans</span>
            <span style={{ fontSize: 12, color: '#94a3b8' }}>{totalScans} total</span>
          </div>
          {scans.slice(0, 8).map(s => {
            const crits = (s.output?.attack_plan ?? []).filter(o => o.priority === 'CRITICAL').length;
            const highs = (s.output?.attack_plan ?? []).filter(o => o.priority === 'HIGH').length;
            return (
              <div key={s.id} style={{ padding: '12px 18px', display: 'flex', alignItems: 'center', gap: 12, borderBottom: '1px solid var(--color-bg-base)' }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--color-text-primary)', flex: 1 }}>{agentName(s)}</span>
                {crits > 0 && <span className="badge badge-critical">{crits} CRIT</span>}
                {highs > 0 && <span className="badge badge-high">{highs} HIGH</span>}
                <span style={{ fontSize: 12, color: '#94a3b8' }}>{formatDate(s.created_at)}</span>
              </div>
            );
          })}
        </div>
      )}

      {scans.length === 0 && (
        <div style={{
          background: '#fff', border: '1px solid var(--color-border)',
          borderRadius: 14, padding: 32, marginTop: 16,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          color: '#94a3b8', fontSize: 14, minHeight: 220,
        }}>
          No scans yet — run your first analysis from the Workspace.
        </div>
      )}
    </div>
  );
}
