'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Plus, X, Brain, Send, ChevronDown, ChevronUp } from 'lucide-react';
import {
  VULN_SCOPE_DIRECT,
  VULN_SCOPE_INDIRECT,
  VULN_SCOPE_MULTITURN,
  VULN_SCOPE_MCP,
  VULN_SCOPE_RAG,
  type VulnScope,
  type ExpertConfig,
} from '@/types';

interface ExpertAnalysisProps {
  onAnalyze: (config: ExpertConfig) => void;
  isAnalyzing: boolean;
}

const DEFAULT_CONFIG: ExpertConfig = {
  agent_name: '',
  mission: '',
  tools: [],
  data_sources: [],
  architecture_notes: '',
  scope: [],
  agent_description: '',
  uses_mcp: false,
  uses_rag: false,
};

function TagInput({
  label,
  placeholder,
  items,
  onAdd,
  onRemove,
}: {
  label: string;
  placeholder: string;
  items: string[];
  onAdd: (value: string) => void;
  onRemove: (index: number) => void;
}) {
  const [input, setInput] = useState('');

  const commit = () => {
    const v = input.trim();
    if (v && !items.includes(v)) {
      onAdd(v);
      setInput('');
    }
  };

  return (
    <div>
      <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
        {label}
      </label>
      <div className="flex gap-2 mb-2">
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ',') {
              e.preventDefault();
              commit();
            }
          }}
          placeholder={placeholder}
          className="input-base flex-1 text-sm"
        />
        <button type="button" onClick={commit} className="btn-ghost px-3">
          <Plus className="w-4 h-4" />
        </button>
      </div>
      {items.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {items.map((item, i) => (
            <span
              key={i}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-medium"
              style={{ background: 'rgba(6,214,160,0.1)', color: '#06d6a0', border: '1px solid rgba(6,214,160,0.2)' }}
            >
              {item}
              <button type="button" onClick={() => onRemove(i)} className="hover:opacity-70 transition-opacity">
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
}


interface ScopeSectionProps {
  label: string;
  options: readonly VulnScope[];
  selected: VulnScope[];
  onToggle: (s: VulnScope) => void;
  accentColor?: string;
  accentBg?: string;
}

function ScopeSection({ label, options, selected, onToggle, accentColor = '#a78bfa', accentBg = 'rgba(167,139,250,0.15)' }: ScopeSectionProps) {
  return (
    <div>
      <p className="text-xs font-semibold mb-2" style={{ color: 'var(--color-text-muted)' }}>
        {label}
      </p>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
        {options.map((scope) => {
          const active = selected.includes(scope);
          return (
            <button
              key={scope}
              type="button"
              onClick={() => onToggle(scope)}
              className="py-2 px-3 rounded-lg text-xs font-medium text-left transition-all duration-150"
              style={{
                background: active ? accentBg : 'var(--color-bg-surface)',
                color: active ? accentColor : 'var(--color-text-secondary)',
                border: `1px solid ${active ? accentColor + '60' : 'var(--color-border)'}`,
              }}
            >
              {scope}
            </button>
          );
        })}
      </div>
    </div>
  );
}

export default function ExpertAnalysis({ onAnalyze, isAnalyzing }: ExpertAnalysisProps) {
  const [config, setConfig] = useState<ExpertConfig>(DEFAULT_CONFIG);
  const [notesOpen, setNotesOpen] = useState(false);

  const update = <K extends keyof ExpertConfig>(key: K, value: ExpertConfig[K]) =>
    setConfig((prev) => ({ ...prev, [key]: value }));

  const addTool = (v: string) => update('tools', [...config.tools, v]);
  const removeTool = (i: number) => update('tools', config.tools.filter((_, idx) => idx !== i));

  const addSource = (v: string) => update('data_sources', [...config.data_sources, v]);
  const removeSource = (i: number) => update('data_sources', config.data_sources.filter((_, idx) => idx !== i));

  const toggleScope = (s: VulnScope) =>
    update(
      'scope',
      config.scope.includes(s) ? config.scope.filter((x) => x !== s) : [...config.scope, s],
    );

  const toggleMcp = (e: React.ChangeEvent<HTMLInputElement>) => {
    const next = e.target.checked;
    const newScope = next
      ? config.scope
      : config.scope.filter((s) => !(VULN_SCOPE_MCP as readonly string[]).includes(s));
    setConfig((prev) => ({ ...prev, uses_mcp: next, scope: newScope }));
  };

  const toggleRag = (e: React.ChangeEvent<HTMLInputElement>) => {
    const next = e.target.checked;
    const newScope = next
      ? config.scope
      : config.scope.filter((s) => !(VULN_SCOPE_RAG as readonly string[]).includes(s));
    setConfig((prev) => ({ ...prev, uses_rag: next, scope: newScope }));
  };

  const isValid = config.agent_name.trim() && config.mission.trim();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isValid || isAnalyzing) return;
    onAnalyze(config);
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {/* Section 0 — Technology checkboxes */}
      <div className="rounded-lg px-4 py-3 space-y-2" style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}>
        <p className="text-xs font-medium" style={{ color: 'var(--color-text-muted)' }}>
          Does your agent use any of the following?
        </p>
        <label className="flex items-center gap-2.5 cursor-pointer group">
          <input
            type="checkbox"
            checked={config.uses_mcp}
            onChange={toggleMcp}
            disabled={isAnalyzing}
            className="w-4 h-4 rounded accent-green-400"
          />
          <span className="text-sm text-black group-hover:opacity-80 transition-opacity">
            MCP tools / servers
          </span>
          <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
            — adds MCP-specific attack checks
          </span>
        </label>
        <label className="flex items-center gap-2.5 cursor-pointer group">
          <input
            type="checkbox"
            checked={config.uses_rag}
            onChange={toggleRag}
            disabled={isAnalyzing}
            className="w-4 h-4 rounded accent-green-400"
          />
          <span className="text-sm text-black group-hover:opacity-80 transition-opacity">
            RAG / knowledge base
          </span>
          <span className="text-xs" style={{ color: 'var(--color-text-muted)' }}>
            — adds RAG poisoning attack checks
          </span>
        </label>
      </div>

      {/* Section 1 — Agent Identity */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-widest mb-6" style={{ color: 'var(--color-text-muted)' }}>
          1 · Agent Identity
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
              Agent name <span style={{ color: 'var(--color-accent-green)' }}>*</span>
            </label>
            <input
              id="expert-agent-name"
              type="text"
              placeholder="e.g. Corporate-Recruiter-Bot"
              value={config.agent_name}
              onChange={(e) => update('agent_name', e.target.value)}
              className="input-base text-sm"
              required
            />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1.5" style={{ color: 'var(--color-text-secondary)' }}>
              Mission / primary goal <span style={{ color: 'var(--color-accent-green)' }}>*</span>
            </label>
            <input
              id="expert-mission"
              type="text"
              placeholder="e.g. Screen resumes and update candidate DB"
              value={config.mission}
              onChange={(e) => update('mission', e.target.value)}
              className="input-base text-sm"
              required
            />
          </div>
        </div>
      </div>

      {/* Section 2 — Tools & Data Sources */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--color-text-muted)' }}>
          2 · Capabilities
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <TagInput
            label="Available tools"
            placeholder="e.g. sql_query_executor (Enter to add)"
            items={config.tools}
            onAdd={addTool}
            onRemove={removeTool}
          />
          <TagInput
            label="Data sources"
            placeholder="e.g. PDF attachments, emails (Enter to add)"
            items={config.data_sources}
            onAdd={addSource}
            onRemove={removeSource}
          />
        </div>
      </div>

      {/* Section 3 — Vulnerability Scope */}
      <div>
        <p className="text-xs font-semibold uppercase tracking-widest mb-3" style={{ color: 'var(--color-text-muted)' }}>
          3 · Testing Scope
          <span className="ml-2 normal-case font-normal" style={{ color: 'var(--color-text-muted)' }}>
            (leave empty to test all active categories)
          </span>
        </p>
        <div className="space-y-8">
          <ScopeSection
            label="Direct Attacks"
            options={VULN_SCOPE_DIRECT}
            selected={config.scope}
            onToggle={toggleScope}
            accentColor="#0ea5e9"
            accentBg="rgba(14,165,233,0.12)"
          />
          <ScopeSection
            label="Indirect Attacks"
            options={VULN_SCOPE_INDIRECT}
            selected={config.scope}
            onToggle={toggleScope}
            accentColor="#f59e0b"
            accentBg="rgba(245,158,11,0.12)"
          />
          <ScopeSection
            label="Multi-turn Attacks"
            options={VULN_SCOPE_MULTITURN}
            selected={config.scope}
            onToggle={toggleScope}
            accentColor="#a78bfa"
            accentBg="rgba(167,139,250,0.15)"
          />
          {config.uses_mcp && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <ScopeSection
                label="MCP Attacks"
                options={VULN_SCOPE_MCP}
                selected={config.scope}
                onToggle={toggleScope}
                accentColor="#06d6a0"
                accentBg="rgba(6,214,160,0.12)"
              />
            </motion.div>
          )}
          {config.uses_rag && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <ScopeSection
                label="RAG Attacks"
                options={VULN_SCOPE_RAG}
                selected={config.scope}
                onToggle={toggleScope}
                accentColor="#f472b6"
                accentBg="rgba(244,114,182,0.12)"
              />
            </motion.div>
          )}
        </div>
      </div>

      {/* Section 4 — Architecture Notes (collapsible) */}
      <div>
        <button
          type="button"
          onClick={() => setNotesOpen((o) => !o)}
          className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest transition-colors"
          style={{ color: 'var(--color-text-muted)' }}
        >
          {notesOpen ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
          4 · Architecture Notes (optional)
        </button>

        {notesOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mt-3"
          >
            <textarea
              id="expert-arch-notes"
              value={config.architecture_notes}
              onChange={(e) => update('architecture_notes', e.target.value)}
              placeholder="Describe APIs, databases, authentication flows, external services, MCP server names, knowledge base type, etc."
              rows={4}
              className="input-base text-sm resize-none"
            />
          </motion.div>
        )}
      </div>

      {/* Submit */}
      <motion.button
        type="submit"
        id="expert-analyze-btn"
        disabled={!isValid || isAnalyzing}
        whileHover={{ scale: !isValid || isAnalyzing ? 1 : 1.015 }}
        whileTap={{ scale: 0.985 }}
        className="btn-primary w-full py-3.5"
        style={
          !isValid
            ? { background: 'var(--color-bg-hover)', color: 'var(--color-text-muted)', boxShadow: 'none' }
            : { background: 'linear-gradient(135deg, #a78bfa, #0ea5e9)' }
        }
      >
        <Brain className="w-4 h-4" />
        <span>{isAnalyzing ? 'Analysing…' : 'Run Expert Analysis'}</span>
        {!isAnalyzing && <Send className="w-4 h-4 ml-auto" />}
      </motion.button>

      {/* Info strip */}
      <div className="grid grid-cols-3 gap-2">
        {[
          { label: 'Required', value: 'Name + Mission' },
          { label: 'Attack paths', value: '5–8 findings' },
          { label: 'Est. time', value: '~20–60s' },
        ].map((item) => (
          <div key={item.label} className="rounded-lg p-2.5 text-center"
               style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}>
            <p className="text-xs mb-0.5" style={{ color: 'var(--color-text-muted)' }}>{item.label}</p>
            <p className="text-xs font-semibold text-white">{item.value}</p>
          </div>
        ))}
      </div>
    </form>
  );
}
