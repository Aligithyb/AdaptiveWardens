"use client"

import {
  ShieldAlert, Globe, Server, Wifi, Eye, Copy, Download,
  AlertTriangle, CheckCircle, Clock, ChevronRight, X, Loader2,
} from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8003';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function vtScoreColor(mal: number): string {
  if (mal === 0) return 'text-green-400';
  if (mal <= 5)  return 'text-yellow-400';
  return 'text-red-400';
}

function abuseColor(score: number): string {
  if (score >= 50) return 'bg-red-500/20 text-red-400 border-red-500/30';
  if (score >= 20) return 'bg-orange-500/20 text-orange-400 border-orange-500/30';
  if (score > 0)   return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30';
  return 'bg-green-500/20 text-green-400 border-green-500/30';
}

function hostingBadge(label: string) {
  const styles: Record<string, string> = {
    'Datacenter': 'bg-purple-500/20 text-purple-300 border-purple-500/30',
    'Tor Exit':   'bg-red-500/20 text-red-300 border-red-500/30',
    'VPN/Proxy':  'bg-orange-500/20 text-orange-300 border-orange-500/30',
    'Mobile ISP': 'bg-blue-500/20 text-blue-300 border-blue-500/30',
    'ISP':        'bg-slate-500/20 text-slate-300 border-slate-500/30',
  };
  const cls = styles[label] || 'bg-slate-700 text-slate-400 border-slate-600';
  return (
    <span className={`px-2 py-0.5 text-xs rounded border ${cls}`}>{label || 'Unknown'}</span>
  );
}

function riskBadge(level: string) {
  const styles: Record<string, string> = {
    Critical: 'bg-red-500/10 text-red-400 border-red-500/30',
    High:     'bg-orange-500/10 text-orange-400 border-orange-500/30',
    Medium:   'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    Low:      'bg-blue-500/10 text-blue-400 border-blue-500/30',
  };
  return (
    <span className={`px-2 py-0.5 text-xs rounded border ${styles[level] || 'bg-slate-700 text-slate-400 border-slate-600'}`}>
      {level || 'Low'}
    </span>
  );
}

function fmtDate(dt: string | null) {
  if (!dt) return '—';
  return new Date(dt).toLocaleString();
}

function NoKey() {
  return <span className="text-slate-600 text-xs">—</span>;
}

// ---------------------------------------------------------------------------
// Detail panel tabs
// ---------------------------------------------------------------------------

function VTTab({ vt }: { vt: any }) {
  if (!vt || vt.error === 'no_key') return (
    <div className="p-4 text-sm text-slate-400">
      VirusTotal API key not configured. Add <code className="text-cyan-400">VIRUSTOTAL_API_KEY</code> to your <code>.env</code>.
    </div>
  );
  if (vt.error) return (
    <div className="p-4 text-sm text-slate-500">Lookup failed: {vt.error}</div>
  );

  const mal  = vt.malicious  || 0;
  const sus  = vt.suspicious || 0;
  const harm = vt.harmless   || 0;
  const und  = vt.undetected || 0;
  const tot  = vt.total_engines || (mal + sus + harm + und);

  return (
    <div className="p-4 space-y-4">
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Malicious',  value: mal,  color: 'text-red-400' },
          { label: 'Suspicious', value: sus,  color: 'text-orange-400' },
          { label: 'Harmless',   value: harm, color: 'text-green-400' },
          { label: 'Undetected', value: und,  color: 'text-slate-400' },
        ].map(s => (
          <div key={s.label} className="bg-slate-800 rounded-lg p-3 text-center">
            <div className={`text-2xl font-bold ${s.color}`}>{s.value}</div>
            <div className="text-xs text-slate-500 mt-1">{s.label}</div>
          </div>
        ))}
      </div>
      <div className="text-sm text-slate-400">
        <span className="text-slate-300">{tot}</span> engines analysed
        {vt.last_analysis_date && (
          <span className="ml-2 text-slate-500">
            · Last scan {new Date(vt.last_analysis_date * 1000).toLocaleDateString()}
          </span>
        )}
      </div>
      {vt.as_owner && (
        <div className="text-sm text-slate-400">AS owner: <span className="text-slate-300">{vt.as_owner}</span> (ASN {vt.asn})</div>
      )}
      {(vt.tags || []).length > 0 && (
        <div className="flex flex-wrap gap-1">
          {vt.tags.map((t: string) => (
            <span key={t} className="px-2 py-0.5 text-xs bg-slate-700 text-slate-300 rounded">{t}</span>
          ))}
        </div>
      )}
      {vt.reputation !== undefined && (
        <div className="text-sm text-slate-400">
          VT Reputation: <span className={vt.reputation < 0 ? 'text-red-400' : 'text-green-400'}>{vt.reputation}</span>
        </div>
      )}
    </div>
  );
}

function AbuseTab({ abuse, ipapi }: { abuse: any; ipapi: any }) {
  if (!abuse || abuse.error === 'no_key') return (
    <div className="p-4 text-sm text-slate-400">
      AbuseIPDB API key not configured. Add <code className="text-cyan-400">ABUSEIPDB_API_KEY</code> to your <code>.env</code>.
    </div>
  );
  if (abuse.error) return (
    <div className="p-4 text-sm text-slate-500">Lookup failed: {abuse.error}</div>
  );

  const score = abuse.abuse_confidence_score || 0;

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center gap-4">
        <div className="flex-1">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-slate-400">Abuse Confidence</span>
            <span className={`text-sm font-bold ${score >= 50 ? 'text-red-400' : score >= 20 ? 'text-orange-400' : 'text-green-400'}`}>
              {score}%
            </span>
          </div>
          <div className="h-2 bg-slate-700 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all ${score >= 50 ? 'bg-red-500' : score >= 20 ? 'bg-orange-400' : 'bg-green-500'}`}
              style={{ width: `${score}%` }}
            />
          </div>
        </div>
      </div>
      <div className="grid grid-cols-2 gap-3 text-sm">
        {[
          { label: 'Total Reports', value: abuse.total_reports || 0 },
          { label: 'Distinct Users', value: abuse.num_distinct_users || 0 },
          { label: 'ISP', value: abuse.isp || (ipapi?.isp) || '—' },
          { label: 'Usage Type', value: abuse.usage_type || '—' },
          { label: 'Domain', value: abuse.domain || '—' },
          { label: 'Is Tor', value: abuse.is_tor ? 'Yes' : 'No' },
        ].map(row => (
          <div key={row.label} className="bg-slate-800 rounded p-2">
            <div className="text-xs text-slate-500">{row.label}</div>
            <div className="text-slate-300 mt-0.5 truncate">{String(row.value)}</div>
          </div>
        ))}
      </div>
      {abuse.last_reported_at && (
        <div className="text-xs text-slate-500">
          Last reported: {fmtDate(abuse.last_reported_at)}
        </div>
      )}
    </div>
  );
}

function SessionHistoryTab({ sessions }: { sessions: any[] }) {
  if (!sessions || sessions.length === 0) return (
    <div className="p-4 text-sm text-slate-500">No sessions from this IP.</div>
  );
  return (
    <div className="overflow-y-auto max-h-72">
      <table className="w-full text-sm">
        <thead className="bg-slate-800/60 sticky top-0">
          <tr>
            {['Session', 'Start', 'Protocol', 'Cmds', 'Techniques', 'Risk'].map(h => (
              <th key={h} className="px-4 py-2 text-left text-xs text-slate-400">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {sessions.map(s => (
            <tr key={s.session_id} className="hover:bg-slate-800/30 transition-colors">
              <td className="px-4 py-2 font-mono text-cyan-400 text-xs">{s.session_id?.slice(0, 8)}…</td>
              <td className="px-4 py-2 text-slate-400 text-xs">{fmtDate(s.start_time)}</td>
              <td className="px-4 py-2">
                <span className="px-1.5 py-0.5 text-xs bg-slate-700 text-slate-300 rounded uppercase">{s.protocol}</span>
              </td>
              <td className="px-4 py-2 text-slate-400">{s.command_count ?? 0}</td>
              <td className="px-4 py-2 text-slate-400">{s.technique_count ?? 0}</td>
              <td className="px-4 py-2">{riskBadge(s.risk_level)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ---------------------------------------------------------------------------
// IP Detail panel
// ---------------------------------------------------------------------------

function IPDetailPanel({ ip, onClose }: { ip: string; onClose: () => void }) {
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState<'vt' | 'abuse' | 'history'>('vt');

  useEffect(() => {
    setLoading(true);
    api.get(`/api/threat-intel/ip/${ip}`, { timeout: 35000 })
      .then(r => setData(r.data))
      .catch(e => console.error('TI detail failed', e))
      .finally(() => setLoading(false));
  }, [ip]);

  const ipapi = data?.ipapi || {};

  return (
    <div className="flex flex-col h-full border-l border-slate-800 bg-slate-900">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-mono text-cyan-400 text-sm">{ip}</span>
          {data && hostingBadge(data.hosting_label)}
          {ipapi.country && (
            <span className="text-xs text-slate-400">{ipapi.country}</span>
          )}
        </div>
        <button onClick={onClose} className="p-1 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800">
          <X className="w-4 h-4" />
        </button>
      </div>

      {loading ? (
        <div className="flex-1 flex items-center justify-center text-slate-500">
          <Loader2 className="w-5 h-5 animate-spin mr-2" /> Enriching…
        </div>
      ) : (
        <>
          {/* ASN / ISP summary */}
          <div className="px-4 py-3 border-b border-slate-800 text-xs text-slate-400 space-y-0.5">
            {ipapi.org && <div>Org: <span className="text-slate-300">{ipapi.org}</span></div>}
            {ipapi.isp && ipapi.isp !== ipapi.org && <div>ISP: <span className="text-slate-300">{ipapi.isp}</span></div>}
            {ipapi.as_info && <div>AS: <span className="text-slate-300">{ipapi.as_info}</span></div>}
            {ipapi.city && <div>Location: <span className="text-slate-300">{ipapi.city}{ipapi.region ? `, ${ipapi.region}` : ''}</span></div>}
          </div>

          {/* Tabs */}
          <div className="flex border-b border-slate-800">
            {([
              { key: 'vt',      label: 'VirusTotal' },
              { key: 'abuse',   label: 'AbuseIPDB' },
              { key: 'history', label: `Sessions (${(data?.sessions || []).length})` },
            ] as const).map(t => (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={`px-4 py-2 text-xs transition-colors ${
                  tab === t.key
                    ? 'text-cyan-400 border-b-2 border-cyan-400'
                    : 'text-slate-400 hover:text-slate-300'
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>

          <div className="flex-1 overflow-y-auto">
            {tab === 'vt'      && <VTTab vt={data?.virustotal} />}
            {tab === 'abuse'   && <AbuseTab abuse={data?.abuseipdb} ipapi={ipapi} />}
            {tab === 'history' && <SessionHistoryTab sessions={data?.sessions || []} />}
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export function ThreatIntelligence() {
  const [ips, setIps] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedIP, setSelectedIP] = useState<string | null>(null);
  const [search, setSearch] = useState('');
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    setLoading(true);
    api.get('/api/threat-intel/ips', { timeout: 60000 })
      .then(r => setIps(r.data.ips || []))
      .catch(e => console.error('TI list failed', e))
      .finally(() => setLoading(false));
  }, []);

  const filtered = ips.filter(row => {
    if (!search) return true;
    const q = search.toLowerCase();
    return (
      row.ip?.includes(q) ||
      row.country?.toLowerCase().includes(q) ||
      (row.ipapi?.org || '').toLowerCase().includes(q) ||
      (row.ipapi?.isp || '').toLowerCase().includes(q)
    );
  });

  const summary = {
    total:    ips.length,
    malicious: ips.filter(r => (r.virustotal?.malicious || 0) > 0).length,
    highAbuse: ips.filter(r => (r.abuseipdb?.abuse_confidence_score || 0) >= 50).length,
    repeat:   ips.filter(r => (r.session_count || 0) > 1).length,
  };

  const downloadBlocklist = async () => {
    setDownloading(true);
    try {
      window.open(`${API_BASE}/api/threat-intel/blocklist`, '_blank');
    } finally {
      setDownloading(false);
    }
  };

  const copyIP = (ip: string) => navigator.clipboard?.writeText(ip);

  return (
    <div className="flex flex-col h-full gap-4">
      {/* Stat cards */}
      <div className="grid grid-cols-4 gap-4 shrink-0">
        {[
          { label: 'Unique Attacker IPs',  value: summary.total,     icon: Globe,          color: 'cyan' },
          { label: 'Confirmed Malicious',   value: summary.malicious, icon: AlertTriangle,  color: 'red' },
          { label: 'High Abuse Score',      value: summary.highAbuse, icon: ShieldAlert,    color: 'orange' },
          { label: 'Repeat Attackers',      value: summary.repeat,    icon: Clock,          color: 'yellow' },
        ].map(card => {
          const Icon = card.icon;
          return (
            <div key={card.label} className={`bg-slate-900 border border-${card.color}-500/20 rounded-lg p-4 flex items-start gap-3`}>
              <div className={`p-2 rounded-lg bg-${card.color}-500/10`}>
                <Icon className={`w-4 h-4 text-${card.color}-400`} />
              </div>
              <div>
                <div className={`text-2xl font-bold text-${card.color}-400`}>{card.value}</div>
                <div className="text-xs text-slate-500 mt-0.5">{card.label}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Table + detail panel */}
      <div className={`flex flex-1 min-h-0 gap-0 bg-slate-900 rounded-lg border border-slate-800 overflow-hidden`}>
        {/* Left: table */}
        <div className={`flex flex-col ${selectedIP ? 'w-3/5' : 'w-full'} transition-all min-w-0`}>
          {/* Toolbar */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800 gap-3 flex-wrap shrink-0">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-100 text-sm font-medium">IP Intelligence</span>
              <span className="text-xs text-slate-500">{filtered.length} IPs</span>
            </div>
            <div className="flex items-center gap-2">
              <input
                type="text"
                placeholder="Search IP, org, country…"
                value={search}
                onChange={e => setSearch(e.target.value)}
                className="bg-slate-800 border border-slate-700 text-slate-300 text-sm rounded-lg px-3 py-1.5 w-48 focus:outline-none focus:border-cyan-500"
              />
              <button
                onClick={downloadBlocklist}
                disabled={downloading}
                className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-slate-800 border border-slate-700 text-slate-300 hover:text-red-400 hover:border-red-500/30 rounded-lg transition-colors disabled:opacity-50"
              >
                <Download className="w-3.5 h-3.5" />
                Blocklist
              </button>
            </div>
          </div>

          {/* Table */}
          <div className="overflow-auto flex-1">
            <table className="w-full text-sm">
              <thead className="bg-slate-800/50 sticky top-0 z-10">
                <tr>
                  {['IP', 'Hosting', 'VT Score', 'Abuse %', 'Sessions', 'Last Seen', 'Country'].map(h => (
                    <th key={h} className="px-4 py-2.5 text-left text-xs text-slate-400 whitespace-nowrap">{h}</th>
                  ))}
                  <th className="px-4 py-2.5 text-xs text-slate-400"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {loading ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-12 text-center text-slate-500 text-sm">
                      <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2" />
                      Fetching threat intelligence… (cold cache may take a moment)
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-10 text-center text-slate-500 text-sm">
                      No attacker IPs found.
                    </td>
                  </tr>
                ) : filtered.map(row => {
                  const vt      = row.virustotal || {};
                  const abuse   = row.abuseipdb  || {};
                  const mal     = vt.malicious || 0;
                  const tot     = vt.total_engines || 0;
                  const abuseScore = abuse.abuse_confidence_score || 0;
                  const isSelected = selectedIP === row.ip;

                  return (
                    <tr
                      key={row.ip}
                      onClick={() => setSelectedIP(isSelected ? null : row.ip)}
                      className={`cursor-pointer transition-colors ${
                        isSelected
                          ? 'bg-cyan-500/5 border-l-2 border-cyan-500'
                          : 'hover:bg-slate-800/30'
                      }`}
                    >
                      <td className="px-4 py-3 font-mono text-cyan-400 text-xs whitespace-nowrap">
                        {row.ip}
                      </td>
                      <td className="px-4 py-3">
                        {hostingBadge(row.hosting_label)}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        {vt.error === 'no_key' ? (
                          <NoKey />
                        ) : vt.error ? (
                          <span className="text-slate-600 text-xs">err</span>
                        ) : (
                          <span className={`text-sm font-mono font-bold ${vtScoreColor(mal)}`}>
                            {mal}/{tot}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {abuse.error === 'no_key' ? (
                          <NoKey />
                        ) : abuse.error ? (
                          <span className="text-slate-600 text-xs">err</span>
                        ) : (
                          <span className={`px-2 py-0.5 text-xs rounded border font-mono ${abuseColor(abuseScore)}`}>
                            {abuseScore}%
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-slate-400">{row.session_count}</td>
                      <td className="px-4 py-3 text-slate-400 text-xs whitespace-nowrap">
                        {row.last_seen ? new Date(row.last_seen).toLocaleDateString() : '—'}
                      </td>
                      <td className="px-4 py-3 text-slate-400 text-xs">{row.country || '—'}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1">
                          <button
                            onClick={e => { e.stopPropagation(); copyIP(row.ip); }}
                            title="Copy IP"
                            className="p-1 rounded text-slate-600 hover:text-slate-300 hover:bg-slate-800 transition-colors"
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                          <ChevronRight className={`w-4 h-4 transition-colors ${isSelected ? 'text-cyan-400' : 'text-slate-600'}`} />
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: detail panel */}
        {selectedIP && (
          <div className="w-2/5 min-w-0">
            <IPDetailPanel ip={selectedIP} onClose={() => setSelectedIP(null)} />
          </div>
        )}
      </div>

      {/* Footer note */}
      <p className="text-xs text-slate-600 shrink-0">
        Results cached 24h (VirusTotal · AbuseIPDB) · 7 days (ip-api.com). Click any row to open the full intelligence panel.
      </p>
    </div>
  );
}
