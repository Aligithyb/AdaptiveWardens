"use client"

import { Clock, Activity, WifiOff, XCircle, ChevronDown, ChevronUp, SlidersHorizontal } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

function ThreatScore({ score }: { score: number }) {
  const s = Math.max(0, Math.min(100, score || 0));
  const color =
    s >= 80 ? '#f87171' :
    s >= 60 ? '#fb923c' :
    s >= 35 ? '#facc15' :
    '#34d399';
  const r = 14, cx = 18, cy = 18;
  const circ = 2 * Math.PI * r;
  const dash = (s / 100) * circ;
  return (
    <div className="flex items-center gap-1.5">
      <svg width="36" height="36" viewBox="0 0 36 36" style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={cx} cy={cy} r={r} fill="none" className="threat-score-track" strokeWidth="3" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="3"
          strokeDasharray={`${dash} ${circ - dash}`} strokeLinecap="round" />
      </svg>
      <span className="text-xs font-bold tabular-nums" style={{ color }}>{s}</span>
    </div>
  );
}

interface LiveSessionsProps {
  selectedSession: string | null;
  setSelectedSession: (id: string) => void;
  onIPClick?: (ip: string) => void;
}

const RISK_LEVELS  = ['All', 'Critical', 'High', 'Medium', 'Low'];
const PROTOCOLS    = ['All', 'SSH', 'HTTP'];
const STATUSES     = ['All', 'Active', 'Idle', 'Closed'];
const DEFAULT_ROWS = 5;

function FilterPill({
  label, active, onClick
}: { label: string; active: boolean; onClick: () => void }) {
  const base = 'px-3 py-1 rounded-full text-xs font-medium border transition-colors cursor-pointer';
  const on   = 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300';
  const off  = 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500';
  return <button className={`${base} ${active ? on : off}`} onClick={onClick}>{label}</button>;
}

export function LiveSessions({ selectedSession, setSelectedSession, onIPClick }: LiveSessionsProps) {
  const [sessions, setSessions]       = useState<any[]>([]);
  const [collapsed, setCollapsed]     = useState(false);
  const [showAll, setShowAll]         = useState(false);
  const [filterRisk, setFilterRisk]   = useState('All');
  const [filterProto, setFilterProto] = useState('All');
  const [filterStatus, setFilterStatus] = useState('All');
  const [showFilters, setShowFilters] = useState(false);

  useEffect(() => {
    const fetchSessions = async () => {
      try {
        const res = await api.get('/api/sessions');
        const fetched = res.data.sessions || [];
        setSessions(fetched);
        if (!selectedSession && fetched.length > 0) setSelectedSession(fetched[0].session_id);
      } catch (err) {
        console.error('Failed to fetch sessions', err);
      }
    };
    fetchSessions();
    const id = setInterval(fetchSessions, 5000);
    return () => clearInterval(id);
  }, [selectedSession, setSelectedSession]);

  const filtered = sessions.filter(s => {
    if (filterRisk   !== 'All' && s.risk_level        !== filterRisk)   return false;
    if (filterProto  !== 'All' && (s.protocol || '').toUpperCase() !== filterProto) return false;
    if (filterStatus !== 'All' && s.lifecycle_status  !== filterStatus) return false;
    return true;
  });

  const visible = showAll ? filtered : filtered.slice(0, DEFAULT_ROWS);
  const activeSessions = sessions.filter(s => s.lifecycle_status === 'Active').length;
  const hasFilters = filterRisk !== 'All' || filterProto !== 'All' || filterStatus !== 'All';

  const getRiskStyle = (level: string) => {
    switch (level) {
      case 'Critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'High':     return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'Medium':   return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'Low':      return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default:         return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const getStatusNode = (status: string) => {
    switch (status) {
      case 'Active': return (
        <span className="flex items-center gap-1.5 text-green-400">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
          </span>
          Active
        </span>
      );
      case 'Idle': return (
        <span className="flex items-center gap-1.5 text-yellow-400">
          <WifiOff className="w-3 h-3" /> Idle
        </span>
      );
      case 'Closed': return (
        <span className="flex items-center gap-1.5 text-slate-500">
          <XCircle className="w-3 h-3" /> Closed
        </span>
      );
      default: return <span className="text-slate-400">{status}</span>;
    }
  };

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b border-slate-800">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Activity className="w-5 h-5 text-cyan-400" />
            <h2 className="text-slate-100">Live Sessions</h2>
            <span className="text-xs text-slate-500">
              {filtered.length !== sessions.length
                ? `${filtered.length} of ${sessions.length}`
                : sessions.length} sessions
            </span>
          </div>
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 text-sm text-slate-400">
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
              </span>
              {activeSessions} active
            </span>
            {/* Filter toggle */}
            <button
              onClick={() => setShowFilters(f => !f)}
              title="Toggle filters"
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
                showFilters || hasFilters
                  ? 'bg-cyan-500/15 border-cyan-500/40 text-cyan-300'
                  : 'bg-slate-800 border-slate-700 text-slate-400 hover:text-slate-200'
              }`}
            >
              <SlidersHorizontal className="w-3.5 h-3.5" />
              Filter
              {hasFilters && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />}
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
              <span className="text-xs text-slate-500 w-14">Risk</span>
              {RISK_LEVELS.map(r => (
                <FilterPill key={r} label={r} active={filterRisk === r} onClick={() => setFilterRisk(r)} />
              ))}
            </div>
            <div className="flex flex-wrap gap-1.5 items-center">
              <span className="text-xs text-slate-500 w-14">Protocol</span>
              {PROTOCOLS.map(p => (
                <FilterPill key={p} label={p} active={filterProto === p} onClick={() => setFilterProto(p)} />
              ))}
            </div>
            <div className="flex flex-wrap gap-1.5 items-center">
              <span className="text-xs text-slate-500 w-14">Status</span>
              {STATUSES.map(s => (
                <FilterPill key={s} label={s} active={filterStatus === s} onClick={() => setFilterStatus(s)} />
              ))}
            </div>
            {hasFilters && (
              <button
                onClick={() => { setFilterRisk('All'); setFilterProto('All'); setFilterStatus('All'); }}
                className="text-xs text-slate-500 hover:text-slate-300 transition-colors mt-1"
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
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Session ID</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">IP Address</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Country</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Protocol</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Start Time</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Commands</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Status</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Risk</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Score</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-6 py-10 text-center text-slate-500 text-sm">
                      {sessions.length === 0
                        ? 'No sessions recorded yet. Waiting for connections…'
                        : 'No sessions match the active filters.'}
                    </td>
                  </tr>
                ) : (
                  visible.map((session) => (
                    <tr
                      key={session.session_id}
                      onClick={() => setSelectedSession(session.session_id)}
                      className={`hover:bg-slate-800/50 transition-colors cursor-pointer ${
                        selectedSession === session.session_id
                          ? 'bg-cyan-500/5 border-l-2 border-l-cyan-500'
                          : ''
                      }`}
                    >
                      <td className="px-6 py-4 text-sm font-mono text-cyan-400">
                        {session.session_id?.slice(0, 8)}…
                      </td>
                      <td className="px-6 py-4 text-sm">
                        {onIPClick ? (
                          <button
                            className="font-mono text-slate-300 hover:text-cyan-400 transition-colors"
                            onClick={e => { e.stopPropagation(); onIPClick(session.source_ip); }}
                          >
                            {session.source_ip}
                          </button>
                        ) : (
                          <span className="text-slate-300">{session.source_ip}</span>
                        )}
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-400">{session.country || '—'}</td>
                      <td className="px-6 py-4">
                        <span className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded uppercase">
                          {session.protocol}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-400">
                        <span className="flex items-center gap-1.5">
                          <Clock className="w-3 h-3" />
                          {new Date(session.start_time).toLocaleTimeString()}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-400">{session.command_count ?? 0}</td>
                      <td className="px-6 py-4 text-sm">{getStatusNode(session.lifecycle_status || 'Active')}</td>
                      <td className="px-6 py-4">
                        <span className={`px-2 py-1 text-xs rounded border ${getRiskStyle(session.risk_level)}`}>
                          {session.risk_level || 'Low'}
                        </span>
                      </td>
                      <td className="px-4 py-4">
                        <ThreatScore score={session.threat_score ?? session.risk_score ?? 0} />
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          {/* Show more / less */}
          {filtered.length > DEFAULT_ROWS && (
            <div className="px-6 py-3 border-t border-slate-800 flex items-center justify-between">
              <span className="text-xs text-slate-500">
                Showing {showAll ? filtered.length : Math.min(DEFAULT_ROWS, filtered.length)} of {filtered.length} sessions
              </span>
              <button
                onClick={() => setShowAll(a => !a)}
                className="text-xs text-cyan-400 hover:text-cyan-300 font-medium transition-colors"
              >
                {showAll ? 'Show less' : `Show all ${filtered.length} sessions`}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
