"use client"

import { Shield, Filter } from 'lucide-react';
import { useState } from 'react';

export function IOCSummary() {
  const [filterType, setFilterType] = useState('all');
  const [filterSeverity, setFilterSeverity] = useState('all');

  const iocs = [
    { type: 'IP', value: '45.142.212.61', session: 'sess-7f8a9b2c', severity: 'High', confidence: 95 },
    { type: 'Domain', value: 'malicious-domain.ru', session: 'sess-7f8a9b2c', severity: 'Critical', confidence: 98 },
    { type: 'IP', value: '103.75.189.44', session: 'sess-3c4d5e6f', severity: 'Critical', confidence: 92 },
    { type: 'File', value: 'payload.sh', session: 'sess-7f8a9b2c', severity: 'High', confidence: 89 },
    { type: 'Domain', value: 'c2-server.com', session: 'sess-7f8a9b2c', severity: 'Critical', confidence: 97 },
    { type: 'IP', value: '185.220.101.33', session: 'sess-9a8b7c6d', severity: 'Medium', confidence: 78 },
    { type: 'File', value: 'cryptominer.exe', session: 'sess-3c4d5e6f', severity: 'High', confidence: 94 },
    { type: 'IP', value: '210.45.78.92', session: 'sess-5d6e7f8a', severity: 'High', confidence: 86 },
  ];

  const filteredIOCs = iocs.filter(ioc => {
    if (filterType !== 'all' && ioc.type !== filterType) return false;
    if (filterSeverity !== 'all' && ioc.severity !== filterSeverity) return false;
    return true;
  });

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'High': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'Medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'Low': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return 'text-green-400';
    if (confidence >= 75) return 'text-yellow-400';
    return 'text-orange-400';
  };

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-orange-400" />
            <h2 className="text-slate-100">IOC Summary</h2>
          </div>
          <span className="text-sm text-slate-400">{filteredIOCs.length} indicators</span>
        </div>

        <div className="flex gap-2">
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Types</option>
            <option value="IP">IP</option>
            <option value="Domain">Domain</option>
            <option value="File">File</option>
          </select>

          <select
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
            className="px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-sm text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="all">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-slate-800/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Type</th>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Value</th>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Session</th>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Severity</th>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Confidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {filteredIOCs.map((ioc, idx) => (
              <tr key={idx} className="hover:bg-slate-800/50 transition-colors">
                <td className="px-6 py-4">
                  <span className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded">
                    {ioc.type}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-slate-300">{ioc.value}</td>
                <td className="px-6 py-4 text-sm text-cyan-400">{ioc.session}</td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 text-xs rounded border ${getSeverityColor(ioc.severity)}`}>
                    {ioc.severity}
                  </span>
                </td>
                <td className="px-6 py-4">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 bg-slate-800 rounded-full h-1.5">
                      <div
                        className={`h-1.5 rounded-full ${
                          ioc.confidence >= 90 ? 'bg-green-400' :
                          ioc.confidence >= 75 ? 'bg-yellow-400' : 'bg-orange-400'
                        }`}
                        style={{ width: `${ioc.confidence}%` }}
                      ></div>
                    </div>
                    <span className={`text-xs ${getConfidenceColor(ioc.confidence)}`}>
                      {ioc.confidence}%
                    </span>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
