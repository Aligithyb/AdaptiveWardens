"use client"

import { Shield, ChevronDown, ChevronUp, SlidersHorizontal } from 'lucide-react';
import { useState, useEffect } from 'react';
import { api } from '@/lib/api';

const DEFAULT_ROWS = 5;

function FilterPill({
  label, active, onClick
}: { label: string; active: boolean; onClick: () => void }) {
  const base = 'px-3 py-1 rounded-full text-xs font-medium border transition-colors cursor-pointer';
  const on   = 'bg-orange-500/15 border-orange-500/40 text-orange-300';
  const off  = 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500';
  return <button className={`${base} ${active ? on : off}`} onClick={onClick}>{label}</button>;
}

const IOC_TYPES   = ['All', 'IP', 'Domain', 'URL', 'Hash', 'File', 'Command'];
const SEVERITIES  = ['All', 'Critical', 'High', 'Medium', 'Low'];

export function IOCSummary({ onIPClick }: { onIPClick?: (ip: string) => void }) {
  const [iocs, setIocs]                   = useState<any[]>([]);
  const [collapsed, setCollapsed]         = useState(false);
  const [showAll, setShowAll]             = useState(false);
  const [showFilters, setShowFilters]     = useState(false);
  const [filterType, setFilterType]       = useState('All');
  const [filterSeverity, setFilterSeverity] = useState('All');

  useEffect(() => {
    const fetchIocs = async () => {
      try {
        const res = await api.get('/api/iocs');
        setIocs(res.data.iocs || []);
      } catch (err) {
        console.error('Failed to fetch IOCs', err);
      }
    };
    fetchIocs();
    const id = setInterval(fetchIocs, 5000);
    return () => clearInterval(id);
  }, []);

  const severityFromConfidence = (c: number) => {
    const p = c * 100;
    if (p >= 95) return 'Critical';
    if (p >= 80) return 'High';
    if (p >= 60) return 'Medium';
    return 'Low';
  };

  const typeLabel = (t: string) => {
    const m: Record<string, string> = { filepath: 'File', command: 'Command', ip: 'IP', domain: 'Domain', url: 'URL', hash: 'Hash' };
    return m[t?.toLowerCase()] || t?.toUpperCase();
  };

  const filtered = iocs.filter(ioc => {
    if (filterType !== 'All' && typeLabel(ioc.ioc_type) !== filterType) return false;
    if (filterSeverity !== 'All' && severityFromConfidence(ioc.confidence) !== filterSeverity) return false;
    return true;
  });

  const visible = showAll ? filtered : filtered.slice(0, DEFAULT_ROWS);
  const hasFilters = filterType !== 'All' || filterSeverity !== 'All';

  const getSeverityColor = (s: string) => {
    switch (s) {
      case 'Critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'High':     return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'Medium':   return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'Low':      return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default:         return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-slate-800">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-5 h-5 text-orange-400" />
            <h2 className="text-slate-100">IOC Summary</h2>
            <span className="text-xs text-slate-500">
              {filtered.length !== iocs.length
                ? `${filtered.length} of ${iocs.length}`
                : iocs.length} indicators
            </span>
          </div>
          <div className="flex items-center gap-2">
            {/* Filter toggle */}
            <button
              onClick={() => setShowFilters(f => !f)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
                showFilters || hasFilters
                  ? 'bg-orange-500/15 border-orange-500/40 text-orange-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              <SlidersHorizontal className="w-3.5 h-3.5" />
              Filter
              {hasFilters && <span className="w-1.5 h-1.5 rounded-full bg-orange-400" />}
            </button>
            {/* Collapse toggle */}
            <button
              onClick={() => setCollapsed(c => !c)}
              title={collapsed ? 'Expand' : 'Collapse'}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              {collapsed ? <ChevronDown className="w-4 h-4" /> : <ChevronUp className="w-4 h-4" />}
            </button>
          </div>
        </div>

        {/* Filter row */}
        {showFilters && (
          <div className="mt-4 space-y-2">
            <div className="flex flex-wrap gap-1.5 items-center">
              <span className="text-xs text-slate-500 w-14">Type</span>
              {IOC_TYPES.map(t => (
                <FilterPill key={t} label={t} active={filterType === t} onClick={() => setFilterType(t)} />
              ))}
            </div>
            <div className="flex flex-wrap gap-1.5 items-center">
              <span className="text-xs text-slate-500 w-14">Severity</span>
              {SEVERITIES.map(s => (
                <FilterPill key={s} label={s} active={filterSeverity === s} onClick={() => setFilterSeverity(s)} />
              ))}
            </div>
            {hasFilters && (
              <button
                onClick={() => { setFilterType('All'); setFilterSeverity('All'); }}
                className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
              >
                Clear filters
              </button>
            )}
          </div>
        )}
      </div>

      {/* Table — hidden when collapsed */}
      {!collapsed && (
        <>
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
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-6 py-10 text-center text-slate-500 text-sm">
                      {iocs.length === 0
                        ? 'No IOCs captured yet.'
                        : 'No IOCs match the active filters.'}
                    </td>
                  </tr>
                ) : (
                  visible.map((ioc, idx) => {
                    const severity = severityFromConfidence(ioc.confidence);
                    const confPct  = Math.round(ioc.confidence * 100);
                    const barColor = confPct >= 90 ? 'bg-green-400' : confPct >= 75 ? 'bg-yellow-400' : 'bg-orange-400';
                    const txtColor = confPct >= 90 ? 'text-green-400' : confPct >= 75 ? 'text-yellow-400' : 'text-orange-400';
                    return (
                      <tr key={idx} className="hover:bg-slate-800/50 transition-colors">
                        <td className="px-6 py-4">
                          <span className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded uppercase">
                            {typeLabel(ioc.ioc_type)}
                          </span>
                        </td>
                        <td className="px-6 py-4 text-sm">
                          {ioc.ioc_type === 'ip' && onIPClick ? (
                            <button
                              className="font-mono text-cyan-400 hover:text-cyan-300 transition-colors"
                              onClick={() => onIPClick(ioc.value)}
                            >
                              {ioc.value}
                            </button>
                          ) : (
                            <span className="font-mono text-slate-300 break-all">{ioc.value}</span>
                          )}
                        </td>
                        <td className="px-6 py-4 text-sm font-mono text-cyan-400">
                          {ioc.session_id?.slice(0, 8)}…
                        </td>
                        <td className="px-6 py-4">
                          <span className={`px-2 py-1 text-xs rounded border ${getSeverityColor(severity)}`}>
                            {severity}
                          </span>
                        </td>
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 bg-slate-800 rounded-full h-1.5 min-w-[60px]">
                              <div className={`h-1.5 rounded-full ${barColor}`} style={{ width: `${confPct}%` }} />
                            </div>
                            <span className={`text-xs tabular-nums ${txtColor}`}>{confPct}%</span>
                          </div>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>

          {/* Show more / less */}
          {filtered.length > DEFAULT_ROWS && (
            <div className="px-6 py-3 border-t border-slate-800 flex items-center justify-between">
              <span className="text-xs text-slate-500">
                Showing {showAll ? filtered.length : Math.min(DEFAULT_ROWS, filtered.length)} of {filtered.length} indicators
              </span>
              <button
                onClick={() => setShowAll(a => !a)}
                className="text-xs text-orange-400 hover:text-orange-300 font-medium transition-colors"
              >
                {showAll ? 'Show less' : `Show all ${filtered.length} indicators`}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
