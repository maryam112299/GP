'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Send, FileCode, Zap } from 'lucide-react';

interface QuickAnalysisProps {
  onAnalyze: (description: string) => void;
  isAnalyzing: boolean;
}

const EXAMPLE_PRESETS = [
  {
    label: 'Recruiter Bot',
    value: `Agent: 'Corporate-Recruiter-Bot'
Mission: Screens resumes and updates the Candidate-SQL-Database.
Tools: sql_query_executor, email_reader, slack_notifier.
Data: Reads PDF attachments from incoming emails.`,
  },
  {
    label: 'Code Assistant',
    value: `Agent: 'Dev-Assistant'
Mission: Answers developer questions and can execute shell commands to run tests.
Tools: bash_executor, file_reader, github_api.
Data: Reads code files and GitHub PR comments.`,
  },
  {
    label: 'Customer Support',
    value: `Agent: 'Support-Agent'
Mission: Handles customer queries and can access CRM and billing systems.
Tools: crm_reader, billing_api, email_sender.
Data: Reads customer emails and support tickets.`,
  },
];

export default function QuickAnalysis({ onAnalyze, isAnalyzing }: QuickAnalysisProps) {
  const [description, setDescription] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (description.trim() && !isAnalyzing) {
      onAnalyze(description);
    }
  };

  return (
    <div>
      {/* Preset buttons */}
      <div className="flex flex-wrap gap-2 mb-4">
        <span className="text-xs self-center" style={{ color: 'var(--color-text-muted)' }}>
          Try an example:
        </span>
        {EXAMPLE_PRESETS.map((preset) => (
          <button
            key={preset.label}
            onClick={() => setDescription(preset.value)}
            className="btn-ghost text-xs py-1 px-3"
          >
            <FileCode className="w-3 h-3" />
            {preset.label}
          </button>
        ))}
      </div>

      <form onSubmit={handleSubmit} className="space-y-3">
        <div className="relative">
          <textarea
            id="quick-agent-description"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder={`Briefly describe your AI agent…\n\nExample:\n  Agent: 'Finance-Bot'\n  Mission: Reads invoices and updates accounting DB.\n  Tools: sql_executor, pdf_reader, email_sender.`}
            rows={9}
            className="input-base font-mono text-sm resize-none"
            style={{ fontSize: '0.82rem', lineHeight: '1.6' }}
            disabled={isAnalyzing}
          />
          <div className="absolute bottom-3 right-3 text-xs" style={{ color: 'var(--color-text-muted)' }}>
            {description.length} chars
          </div>
        </div>

        <motion.button
          type="submit"
          id="quick-analyze-btn"
          disabled={!description.trim() || isAnalyzing}
          whileHover={{ scale: !description.trim() || isAnalyzing ? 1 : 1.015 }}
          whileTap={{ scale: 0.985 }}
          className="btn-primary w-full py-3.5"
        >
          <Zap className="w-4 h-4" />
          <span>{isAnalyzing ? 'Analysing…' : 'Run Quick Analysis'}</span>
          {!isAnalyzing && <Send className="w-4 h-4 ml-auto" />}
        </motion.button>
      </form>

      {/* Info strip */}
      <div className="mt-4 grid grid-cols-3 gap-2">
        {[
          { label: 'Required', value: 'Description only' },
          { label: 'Attack paths', value: '3–5 findings' },
          { label: 'Est. time', value: '~10–30s' },
        ].map((item) => (
          <div key={item.label} className="rounded-lg p-2.5 text-center" style={{ background: 'var(--color-bg-surface)', border: '1px solid var(--color-border)' }}>
            <p className="text-xs mb-0.5" style={{ color: 'var(--color-text-muted)' }}>{item.label}</p>
            <p className="text-xs font-semibold text-white">{item.value}</p>
          </div>
        ))}
      </div>
    </div>
  );
}
