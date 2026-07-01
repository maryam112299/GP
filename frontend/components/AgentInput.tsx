/* eslint-disable react/no-unescaped-entities */
'use client';

import { useState } from 'react';
import { motion } from 'framer-motion';
import { Send, FileCode } from 'lucide-react';

interface AgentInputProps {
  onAnalyze: (description: string) => void;
  isAnalyzing: boolean;
}

const exampleAgent = `Agent: 'Corporate-Recruiter-Bot'
Mission: Screens resumes and updates the 'Candidate-SQL-Database'.
Tools: 'sql_query_executor', 'email_reader', 'slack_notifier'.
Data: Reads PDF attachments from incoming emails.`;

export default function AgentInput({ onAnalyze, isAnalyzing }: AgentInputProps) {
  const [description, setDescription] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (description.trim() && !isAnalyzing) {
      onAnalyze(description);
    }
  };

  const loadExample = () => {
    setDescription(exampleAgent);
  };

  return (
    <div className="glass-dark rounded-2xl p-8 border border-cyan-500/30 shadow-2xl">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h2 className="text-2xl font-bold text-white mb-2">Agent Description</h2>
          <p className="text-gray-400 text-sm">
            Describe your AI agent's mission, tools, and data sources
          </p>
        </div>
        <button
          onClick={loadExample}
          className="flex items-center space-x-2 px-4 py-2 bg-green-500/20 hover:bg-green-500/30 
                     text-green-300 rounded-lg border border-green-500/30 transition-all duration-200"
        >
          <FileCode className="w-4 h-4" />
          <span className="text-sm">Load Example</span>
        </button>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div className="relative">
          <textarea
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Enter agent description here..."
            rows={12}
            className="w-full px-4 py-3 bg-slate-900/50 border border-gray-700 rounded-xl 
                     text-white placeholder-gray-500 focus:outline-none focus:ring-2 
                     focus:ring-cyan-500 focus:border-transparent resize-none font-mono text-sm"
            disabled={isAnalyzing}
          />
          <div className="absolute bottom-3 right-3 text-xs text-gray-500">
            {description.length} characters
          </div>
        </div>

        <motion.button
          type="submit"
          disabled={!description.trim() || isAnalyzing}
          whileHover={{ scale: 1.02 }}
          whileTap={{ scale: 0.98 }}
          className={`w-full py-4 px-6 rounded-xl font-semibold text-white 
                    flex items-center justify-center space-x-2 transition-all duration-200
                    ${!description.trim() || isAnalyzing
              ? 'bg-gray-700 cursor-not-allowed'
              : 'bg-gradient-to-r from-cyan-500 to-green-600 hover:from-cyan-600 hover:to-green-700 shadow-lg shadow-green-500/50'
            }`}
        >
          <Send className="w-5 h-5" />
          <span>{isAnalyzing ? 'Analyzing...' : 'Start Security Analysis'}</span>
        </motion.button>
      </form>

      {/* Info Cards */}
      <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-3">
        <div className="bg-slate-900/30 rounded-lg p-3 border border-gray-700/50">
          <p className="text-xs text-gray-400 mb-1">Required Fields</p>
          <p className="text-white text-sm font-medium">Agent, Mission, Tools</p>
        </div>
        <div className="bg-slate-900/30 rounded-lg p-3 border border-gray-700/50">
          <p className="text-xs text-gray-400 mb-1">Analysis Time</p>
          <p className="text-white text-sm font-medium">~10-30 seconds</p>
        </div>
        <div className="bg-slate-900/30 rounded-lg p-3 border border-gray-700/50">
          <p className="text-xs text-gray-400 mb-1">Output Format</p>
          <p className="text-white text-sm font-medium">JSON Mission File</p>
        </div>
      </div>
    </div>
  );
}
