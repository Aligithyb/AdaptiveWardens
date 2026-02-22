"use client"

import { Map, Info } from 'lucide-react';
import { useState } from 'react';

export function MitreAttackMap() {
  const [selectedTechnique, setSelectedTechnique] = useState<string | null>(null);

  const techniques = [
    { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', count: 8, severity: 'high' },
    { id: 'T1078', name: 'Valid Accounts', tactic: 'Defense Evasion', count: 5, severity: 'medium' },
    { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', count: 12, severity: 'critical' },
    { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', count: 6, severity: 'high' },
    { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', count: 15, severity: 'critical' },
    { id: 'T1003', name: 'OS Credential Dumping', tactic: 'Credential Access', count: 4, severity: 'high' },
    { id: 'T1082', name: 'System Information Discovery', tactic: 'Discovery', count: 9, severity: 'medium' },
    { id: 'T1105', name: 'Ingress Tool Transfer', tactic: 'Command and Control', count: 7, severity: 'high' },
    { id: 'T1567', name: 'Exfiltration Over Web Service', tactic: 'Exfiltration', count: 3, severity: 'critical' },
    { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'Defense Evasion', count: 2, severity: 'medium' },
    { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', count: 1, severity: 'critical' },
    { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'Persistence', count: 3, severity: 'medium' },
  ];

  const tactics = [
    'Initial Access',
    'Execution',
    'Persistence',
    'Credential Access',
    'Discovery',
    'Defense Evasion',
    'Command and Control',
    'Exfiltration',
    'Impact'
  ];

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'bg-red-500';
      case 'high': return 'bg-orange-500';
      case 'medium': return 'bg-yellow-500';
      case 'low': return 'bg-blue-500';
      default: return 'bg-slate-700';
    }
  };

  const getIntensity = (count: number) => {
    if (count >= 10) return 100;
    if (count >= 7) return 80;
    if (count >= 4) return 60;
    return 40;
  };

  const selectedTechniqueData = techniques.find(t => t.id === selectedTechnique);

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Map className="w-5 h-5 text-purple-400" />
          <h2 className="text-slate-100">MITRE ATT&CK Mapping</h2>
        </div>
        <span className="text-sm text-slate-400">{techniques.length} techniques detected</span>
      </div>

      <div className="p-6">
        <div className="grid grid-cols-3 gap-2 mb-4">
          {techniques.map((technique) => (
            <button
              key={technique.id}
              onClick={() => setSelectedTechnique(technique.id)}
              className={`relative p-3 rounded-lg border transition-all ${
                selectedTechnique === technique.id
                  ? 'border-cyan-500 bg-cyan-500/10'
                  : 'border-slate-700 hover:border-slate-600'
              }`}
              style={{
                background: selectedTechnique !== technique.id
                  ? `linear-gradient(135deg, ${
                      technique.severity === 'critical' ? 'rgba(239, 68, 68, 0.1)' :
                      technique.severity === 'high' ? 'rgba(249, 115, 22, 0.1)' :
                      technique.severity === 'medium' ? 'rgba(234, 179, 8, 0.1)' :
                      'rgba(59, 130, 246, 0.1)'
                    } 0%, rgba(15, 23, 42, 0) 100%)`
                  : undefined
              }}
            >
              <div className="flex items-start justify-between mb-2">
                <span className="text-xs text-slate-400">{technique.id}</span>
                <span className={`w-6 h-6 rounded flex items-center justify-center text-xs ${
                  technique.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                  technique.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                  technique.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                  'bg-blue-500/20 text-blue-400'
                }`}>
                  {technique.count}
                </span>
              </div>
              <div className="text-xs text-slate-300 line-clamp-2">{technique.name}</div>
              <div className="text-xs text-slate-500 mt-1">{technique.tactic}</div>
              
              <div className="absolute bottom-0 left-0 right-0 h-1 bg-slate-800 rounded-b-lg overflow-hidden">
                <div
                  className={getSeverityColor(technique.severity)}
                  style={{
                    width: `${getIntensity(technique.count)}%`,
                    opacity: getIntensity(technique.count) / 100
                  }}
                ></div>
              </div>
            </button>
          ))}
        </div>

        {selectedTechniqueData && (
          <div className="mt-4 p-4 bg-slate-800/50 border border-slate-700 rounded-lg">
            <div className="flex items-start gap-3">
              <Info className="w-5 h-5 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <div className="flex items-center gap-3 mb-2">
                  <span className="text-slate-100">{selectedTechniqueData.id}</span>
                  <span className={`px-2 py-1 text-xs rounded ${
                    selectedTechniqueData.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                    selectedTechniqueData.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                    selectedTechniqueData.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                    'bg-blue-500/20 text-blue-400'
                  }`}>
                    {selectedTechniqueData.severity}
                  </span>
                </div>
                <h4 className="text-sm text-slate-200 mb-1">{selectedTechniqueData.name}</h4>
                <p className="text-xs text-slate-400 mb-2">Tactic: {selectedTechniqueData.tactic}</p>
                <p className="text-xs text-slate-500">
                  Detected {selectedTechniqueData.count} times across active sessions
                </p>
              </div>
            </div>
          </div>
        )}

        <div className="mt-4 flex items-center gap-4 text-xs">
          <span className="text-slate-400">Severity:</span>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-red-500 rounded"></div>
            <span className="text-slate-500">Critical</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-orange-500 rounded"></div>
            <span className="text-slate-500">High</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-yellow-500 rounded"></div>
            <span className="text-slate-500">Medium</span>
          </div>
          <div className="flex items-center gap-2">
            <div className="w-3 h-3 bg-blue-500 rounded"></div>
            <span className="text-slate-500">Low</span>
          </div>
        </div>
      </div>
    </div>
  );
}
