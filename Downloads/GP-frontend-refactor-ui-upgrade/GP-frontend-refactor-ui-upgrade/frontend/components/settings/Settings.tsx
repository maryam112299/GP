'use client';

import { useState } from 'react';
import type { UserProfile } from '@/types';

interface SettingsProps { user: UserProfile; }

function Toggle({ on, onToggle }: { on: boolean; onToggle: () => void }) {
  return (
    <span
      onClick={onToggle}
      style={{
        width: 38, height: 22, borderRadius: 9999,
        background: on ? 'var(--color-accent)' : '#e2e8f0',
        display: 'flex', alignItems: 'center', padding: 2, flexShrink: 0,
        cursor: 'pointer', transition: 'background .2s',
      }}
    >
      <span style={{
        width: 18, height: 18, borderRadius: '50%', background: '#fff',
        boxShadow: '0 1px 2px rgba(0,0,0,.2)',
        marginLeft: on ? 'auto' : 0,
        transition: 'margin .2s',
      }} />
    </span>
  );
}

function SettingRow({
  title, desc, on, onToggle,
}: { title: string; desc: string; on: boolean; onToggle: () => void }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
      <div>
        <div style={{ fontSize: 14, color: 'var(--color-text-primary)', fontWeight: 500 }}>{title}</div>
        <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 2 }}>{desc}</div>
      </div>
      <Toggle on={on} onToggle={onToggle} />
    </div>
  );
}

export default function Settings({ user }: SettingsProps) {
  const load = <T,>(key: string, def: T): T => {
    try { return JSON.parse(localStorage.getItem(key) ?? 'null') ?? def; } catch { return def; }
  };

  const [expertDefault, setExpertDefault] = useState(() => load('pref_expert', false));
  const [mcpDefault,    setMcpDefault]    = useState(() => load('pref_mcp', true));
  const [emailNotify,   setEmailNotify]   = useState(() => load('pref_email_notify', true));

  const toggle = (key: string, val: boolean, set: (v: boolean) => void) => {
    const next = !val;
    localStorage.setItem(key, JSON.stringify(next));
    set(next);
  };

  const card = (title: string, children: React.ReactNode) => (
    <div style={{
      background: '#fff', border: '1px solid var(--color-border)',
      borderRadius: 14, padding: 24, marginTop: 16,
    }}>
      <div style={{ fontSize: 15, fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: 16 }}>{title}</div>
      {children}
    </div>
  );

  return (
    <div style={{ padding: '28px 32px', maxWidth: 680, animation: 'fadeUp .35s ease' }}>
      <div style={{ fontSize: 22, fontWeight: 700, color: 'var(--color-text-primary)' }}>Settings</div>
      <div style={{ fontSize: 14, color: '#64748b', marginTop: 4 }}>
        Configure default analysis behaviour and account preferences.
      </div>

      {card('Analysis Defaults', (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <SettingRow
            title="Default to Expert mode"
            desc="Start new scans with the deep configuration form."
            on={expertDefault}
            onToggle={() => toggle('pref_expert', expertDefault, setExpertDefault)}
          />
          <div style={{ height: 1, background: 'var(--color-bg-base)' }} />
          <SettingRow
            title="Enable MCP testing by default"
            desc="Include MCP-specific attack surface in every scan."
            on={mcpDefault}
            onToggle={() => toggle('pref_mcp', mcpDefault, setMcpDefault)}
          />
        </div>
      ))}

      {card('Notifications', (
        <SettingRow
          title="Email me on critical findings"
          desc={user.email}
          on={emailNotify}
          onToggle={() => toggle('pref_email_notify', emailNotify, setEmailNotify)}
        />
      ))}
    </div>
  );
}
