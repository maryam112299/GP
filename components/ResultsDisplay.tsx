'use client';

import { motion } from 'framer-motion';
import { Download, Shield, AlertTriangle, Info, Target, Crosshair } from 'lucide-react';
import { MissionFile, AttackObjective } from '@/types';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface ResultsDisplayProps {
  results: MissionFile;
}

const priorityColors = {
  CRITICAL: 'bg-red-500/20 border-red-500 text-red-400',
  HIGH: 'bg-orange-500/20 border-orange-500 text-orange-400',
  MEDIUM: 'bg-yellow-500/20 border-yellow-500 text-yellow-400',
  LOW: 'bg-blue-500/20 border-blue-500 text-blue-400',
};

const priorityIcons = {
  CRITICAL: '🔴',
  HIGH: '🟠',
  MEDIUM: '🟡',
  LOW: '🔵',
};

export default function ResultsDisplay({ results }: ResultsDisplayProps) {
  const downloadJSON = () => {
    const dataStr = JSON.stringify(results, null, 2);
    const dataUri = 'data:application/json;charset=utf-8,' + encodeURIComponent(dataStr);
    const exportFileDefaultName = `mission_file_${results.agent_id}.json`;

    const linkElement = document.createElement('a');
    linkElement.setAttribute('href', dataUri);
    linkElement.setAttribute('download', exportFileDefaultName);
    linkElement.click();
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      className="mt-8 space-y-6"
    >
      {/* Header with Download */}
      <div className="glass-dark rounded-xl p-6 border border-green-500/30">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-3 bg-green-500/20 rounded-lg">
              <Shield className="w-6 h-6 text-green-400" />
            </div>
            <div>
              <h3 className="text-xl font-bold text-white">Analysis Complete</h3>
              <p className="text-gray-400 text-sm">Agent ID: {results.agent_id}</p>
            </div>
          </div>
          <motion.button
            onClick={downloadJSON}
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            className="flex items-center space-x-2 px-4 py-2 bg-green-500/20 hover:bg-green-500/30 
                     text-green-300 rounded-lg border border-green-500/30 transition-all duration-200"
          >
            <Download className="w-4 h-4" />
            <span>Export JSON</span>
          </motion.button>
        </div>
      </div>

      {/* Risk Summary */}
      <div className="glass-dark rounded-xl p-6 border border-cyan-500/30">
        <div className="flex items-start space-x-3 mb-4">
          <div className="p-2 bg-cyan-500/20 rounded-lg">
            <Info className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white mb-2">Risk Summary</h3>
            <p className="text-gray-300 leading-relaxed">{results.risk_summary}</p>
          </div>
        </div>
      </div>

      {/* Attack Plan */}
      <div className="glass-dark rounded-xl p-6 border border-green-500/30">
        <div className="flex items-center space-x-3 mb-6">
          <div className="p-2 bg-green-500/20 rounded-lg">
            <Target className="w-5 h-5 text-green-400" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-white">Attack Plan</h3>
            <p className="text-gray-400 text-sm">{results.attack_plan.length} vulnerabilities identified</p>
          </div>
        </div>

        <div className="space-y-4">
          {results.attack_plan.map((attack: AttackObjective, index: number) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: index * 0.1 }}
              className="bg-slate-900/50 rounded-lg p-5 border border-gray-700/50 hover:border-green-500/50 transition-all duration-200"
            >
              <div className="flex items-start justify-between mb-4">
                <div className="flex items-center space-x-3">
                  <span className="text-2xl">{priorityIcons[attack.priority]}</span>
                  <div>
                    <h4 className="text-white font-semibold text-lg">{attack.vulnerability_type}</h4>
                    <div className="flex items-center space-x-2 mt-1">
                      <span className={`px-2 py-1 rounded text-xs font-medium border ${priorityColors[attack.priority]}`}>
                        {attack.priority}
                      </span>
                      <span className="text-xs text-gray-400">Target: {attack.target_asset}</span>
                    </div>
                  </div>
                </div>
                <Crosshair className="w-5 h-5 text-green-400" />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                <div className="space-y-2">
                  <div>
                    <p className="text-xs text-gray-400 mb-1">MAESTRO Layer</p>
                    <p className="text-sm text-cyan-300 font-medium">{attack.maestro_layer}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-400 mb-1">ATFAA Domain</p>
                    <p className="text-sm text-green-300 font-medium">{attack.atfaa_domain}</p>
                  </div>
                  <div>
                    <p className="text-xs text-gray-400 mb-1">Injection Type</p>
                    <p className="text-sm text-green-300 font-medium">{attack.injection_type}</p>
                  </div>
                </div>

                <div className="space-y-2">
                  <div>
                    <p className="text-xs text-gray-400 mb-1">Exploit Strategy</p>
                    <p className="text-sm text-gray-300">{attack.exploit_strategy}</p>
                  </div>
                </div>
              </div>

              <div className="bg-slate-800/50 rounded-lg p-4 border border-yellow-500/30">
                <div className="flex items-start space-x-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <p className="text-xs text-yellow-400 font-medium mb-1">Adversarial Objective</p>
                    <p className="text-sm text-gray-300">{attack.adversarial_objective}</p>
                  </div>
                </div>
              </div>
            </motion.div>
          ))}
        </div>
      </div>

      {/* JSON Output */}
      <div className="glass-dark rounded-xl overflow-hidden border border-gray-700/50">
        <div className="bg-slate-900/50 px-6 py-3 border-b border-gray-700/50">
          <h3 className="text-sm font-semibold text-white">Raw JSON Output</h3>
        </div>
        <div className="max-h-96 overflow-auto">
          <SyntaxHighlighter
            language="json"
            style={vscDarkPlus}
            customStyle={{
              margin: 0,
              background: 'transparent',
              fontSize: '0.875rem',
            }}
          >
            {JSON.stringify(results, null, 2)}
          </SyntaxHighlighter>
        </div>
      </div>
    </motion.div>
  );
}
