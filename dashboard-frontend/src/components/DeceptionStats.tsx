"use client"

import { useEffect, useState } from 'react';
import { api } from '@/lib/api';
import { ShieldCheck, Terminal, Clock, TrendingUp, Target, Cpu } from 'lucide-react';

function RiskBar({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  const pct = total > 0 ? Math.round((value / total) * 100) : 0;
  return (
    <div className="flex items-center gap-3">
      <span className={`w-16 text-xs ${color} shrink-0`}>{label}</span>
      <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${color.replace('text-', 'bg-')}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="w-8 text-xs text-slate-400 text-right">{value}</span>
    </div>
  );
}

export function DeceptionStats() {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const load = async () => {
      try {
        const res = await api.get('/api/analytics/effectiveness');
        setData(res.data);
      } catch {
        // non-fatal
      } finally {
        setLoading(false);
      }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);

  const engagementRate = data?.engagement_rate ?? 0;
  const engagementColor =
    engagementRate >= 70 ? 'text-green-400' :
    engagementRate >= 40 ? 'text-yellow-400' :
    'text-red-400';

  const riskDist = data?.risk_distribution ?? { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const total = data?.total_sessions ?? 0;

  const formatDuration = (s: number) => {
    if (!s) return '—';
    if (s < 60) return `${s}s`;
    const m = Math.floor(s / 60);
    const sec = s % 60;
    return sec > 0 ? `${m}m ${sec}s` : `${m}m`;
  };

  return (
    <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-800 flex items-center gap-3">
        <div className="w-9 h-9 bg-emerald-500/10 rounded-lg flex items-center justify-center">
          <ShieldCheck className="w-5 h-5 text-emerald-400" />
        </div>
        <div>
          <h2 className="text-slate-100 font-semibold text-sm">Deception Effectiveness</h2>
          <p className="text-xs text-slate-500">How well the honeypot is fooling attackers</p>
        </div>
      </div>

      {loading ? (
        <div className="px-6 py-10 text-center text-slate-500 text-sm animate-pulse">
          Loading effectiveness data…
        </div>
      ) : (
        <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Left — KPI cards */}
          <div className="space-y-4 lg:col-span-1">
            {/* Engagement rate */}
            <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-emerald-400" />
                  <span className="text-xs text-slate-400">Engagement Rate</span>
                </div>
                <span className="text-xs text-slate-500">≥5 cmds</span>
              </div>
              <div className={`text-3xl font-bold ${engagementColor}`}>
                {engagementRate}%
              </div>
              <div className="text-xs text-slate-500 mt-1">
                {data?.engaged_sessions ?? 0} of {total} sessions
              </div>
              {/* Mini arc */}
              <div className="mt-3 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full ${engagementColor.replace('text-', 'bg-')}`}
                  style={{ width: `${engagementRate}%`, transition: 'width 0.7s ease' }}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-3">
              <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
                <Terminal className="w-4 h-4 text-cyan-400 mb-2" />
                <div className="text-xl font-bold text-cyan-400">{data?.avg_commands_per_session ?? '—'}</div>
                <div className="text-xs text-slate-500">Avg cmds / session</div>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
                <Clock className="w-4 h-4 text-purple-400 mb-2" />
                <div className="text-xl font-bold text-purple-400">{formatDuration(data?.avg_session_duration_s)}</div>
                <div className="text-xs text-slate-500">Avg duration</div>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
                <Target className="w-4 h-4 text-orange-400 mb-2" />
                <div className="text-xl font-bold text-orange-400">{data?.unique_techniques_seen ?? 0}</div>
                <div className="text-xs text-slate-500">Unique MITRE techniques</div>
              </div>
              <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700">
                <Cpu className="w-4 h-4 text-pink-400 mb-2" />
                <div className="text-xl font-bold text-pink-400">{data?.unique_ioc_types_seen ?? 0}</div>
                <div className="text-xs text-slate-500">IOC types captured</div>
              </div>
            </div>
          </div>

          {/* Center — Risk distribution */}
          <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">
              Risk Distribution
            </h3>
            <div className="space-y-3">
              <RiskBar label="Critical" value={riskDist.Critical} total={total} color="text-red-400" />
              <RiskBar label="High"     value={riskDist.High}     total={total} color="text-orange-400" />
              <RiskBar label="Medium"   value={riskDist.Medium}   total={total} color="text-yellow-400" />
              <RiskBar label="Low"      value={riskDist.Low}      total={total} color="text-blue-400" />
            </div>
            <div className="mt-5 pt-4 border-t border-slate-700 text-center">
              <div className="text-2xl font-bold text-slate-100">{total}</div>
              <div className="text-xs text-slate-500">Total sessions recorded</div>
            </div>
          </div>

          {/* Right — Top commands */}
          <div className="bg-slate-800/50 rounded-lg p-4 border border-slate-700">
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-4">
              Top Attacker Commands
            </h3>
            {(data?.top_commands ?? []).length === 0 ? (
              <p className="text-sm text-slate-500">No commands recorded yet.</p>
            ) : (
              <ol className="space-y-2.5">
                {(data?.top_commands ?? []).map((cmd: any, i: number) => {
                  const maxCount = data.top_commands[0]?.count || 1;
                  const pct = Math.round((cmd.count / maxCount) * 100);
                  return (
                    <li key={i} className="space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono text-slate-300 truncate max-w-[85%]"
                          title={cmd.command}>
                          {i + 1}. {cmd.command.length > 36 ? cmd.command.slice(0, 36) + '…' : cmd.command}
                        </span>
                        <span className="text-xs text-slate-500 shrink-0 ml-2">{cmd.count}×</span>
                      </div>
                      <div className="h-1 bg-slate-700 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-cyan-500/60 rounded-full"
                          style={{ width: `${pct}%`, transition: 'width 0.7s ease' }}
                        />
                      </div>
                    </li>
                  );
                })}
              </ol>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
