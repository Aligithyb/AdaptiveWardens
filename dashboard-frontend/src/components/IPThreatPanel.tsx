"use client";

import { useEffect, useState } from 'react';
import { X, Loader2, ShieldX, ShieldAlert, ShieldCheck, AlertTriangle, ChevronDown, ChevronRight, ExternalLink } from 'lucide-react';
import { api } from '@/lib/api';

// Module-level 1-hour cache so repeated opens of the same IP are instant.
const _cache = new Map<string, { data: any; at: number }>();
const CACHE_MS = 60 * 60 * 1000;

function overallBadge(data: any) {
  const vtMal  = data?.virustotal?.malicious  ?? 0;
  const vtSus  = data?.virustotal?.suspicious ?? 0;
  const abuse  = data?.abuseipdb?.abuse_confidence_score ?? 0;

  if (vtMal > 0)             return { label: 'Known Malicious', cls: 'bg-red-500/20 text-red-400 border-red-500/40',    Icon: ShieldX     };
  if (abuse >= 50 || vtSus > 0) return { label: 'Suspicious',  cls: 'bg-orange-500/20 text-orange-400 border-orange-500/40', Icon: ShieldAlert };
  return                           { label: 'Clean',            cls: 'bg-green-500/20 text-green-400 border-green-500/40',  Icon: ShieldCheck };
}

function AbuseBar({ score }: { score: number }) {
  const bar  = score >= 50 ? 'bg-red-500'    : score >= 20 ? 'bg-yellow-400'  : 'bg-green-500';
  const text = score >= 50 ? 'text-red-400'  : score >= 20 ? 'text-yellow-400': 'text-green-400';
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs text-slate-400">Abuse Confidence Score</span>
        <span className={`text-sm font-bold ${text}`}>{score}%</span>
      </div>
      <div className="h-2.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full transition-all ${bar}`} style={{ width: `${score}%` }} />
      </div>
    </div>
  );
}

export function IPThreatPanel({ ip, onClose }: { ip: string; onClose: () => void }) {
  const [data, setData]           = useState<any>(null);
  const [loading, setLoading]     = useState(true);
  const [fetchErr, setFetchErr]   = useState<string | null>(null);
  const [detailsOpen, setDetailsOpen] = useState(false);

  useEffect(() => {
    const hit = _cache.get(ip);
    if (hit && Date.now() - hit.at < CACHE_MS) {
      setData(hit.data);
      setLoading(false);
      return;
    }
    setLoading(true);
    setFetchErr(null);
    setData(null);
    api.get(`/api/threat-intel/ip/${ip}`, { timeout: 35000 })
      .then(r => { _cache.set(ip, { data: r.data, at: Date.now() }); setData(r.data); })
      .catch(() => setFetchErr('Failed to fetch threat intelligence. Please try again.'))
      .finally(() => setLoading(false));
  }, [ip]);

  const vt    = data?.virustotal || {};
  const abuse = data?.abuseipdb  || {};
  const ipapi = data?.ipapi      || {};
  const badge = data ? overallBadge(data) : null;

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/50 z-40" onClick={onClose} />

      {/* Panel */}
      <div className="fixed right-0 top-0 h-full w-[460px] bg-slate-900 border-l border-slate-700 z-50 flex flex-col shadow-2xl">

        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 shrink-0">
          <div className="flex items-center gap-2 min-w-0 flex-wrap">
            <span className="font-mono text-cyan-400 text-sm font-semibold">{ip}</span>
            {ipapi.country && <span className="text-xs text-slate-500">· {ipapi.country}</span>}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors flex-shrink-0 ml-2"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto">
          {loading ? (
            <div className="flex flex-col items-center justify-center h-48 gap-3 text-slate-500">
              <Loader2 className="w-6 h-6 animate-spin" />
              <span className="text-sm">Fetching threat intelligence…</span>
            </div>
          ) : fetchErr ? (
            <div className="flex flex-col items-center justify-center h-48 gap-2 text-slate-500">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <span className="text-sm text-center px-6">{fetchErr}</span>
            </div>
          ) : (
            <div className="p-5 space-y-5">

              {/* Overall badge */}
              {badge && (
                <div className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border ${badge.cls}`}>
                  <badge.Icon className="w-4 h-4 flex-shrink-0" />
                  <span className="text-sm font-semibold">{badge.label}</span>
                </div>
              )}

              {/* ISP / location summary */}
              {(ipapi.isp || ipapi.org || ipapi.city) && (
                <div className="bg-slate-800/60 rounded-lg px-4 py-3 space-y-0.5">
                  {ipapi.isp && <p className="text-sm text-slate-300">{ipapi.isp}</p>}
                  {ipapi.org && ipapi.org !== ipapi.isp && (
                    <p className="text-xs text-slate-400">{ipapi.org}</p>
                  )}
                  {ipapi.city && (
                    <p className="text-xs text-slate-500">
                      {ipapi.city}{ipapi.region ? `, ${ipapi.region}` : ''}
                      {ipapi.country ? ` · ${ipapi.country}` : ''}
                    </p>
                  )}
                </div>
              )}

              {/* ── AbuseIPDB ── */}
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <div className="w-1 h-4 bg-orange-400 rounded-full" />
                  <h3 className="text-sm font-semibold text-slate-200">AbuseIPDB</h3>
                </div>

                {abuse.error === 'no_key' ? (
                  <p className="text-xs text-slate-500">API key not configured.</p>
                ) : abuse.error ? (
                  <p className="text-xs text-slate-500">Lookup failed: {abuse.error}</p>
                ) : (
                  <div className="space-y-3">
                    <AbuseBar score={abuse.abuse_confidence_score ?? 0} />
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        { label: 'Total Reports',   value: abuse.total_reports      ?? 0 },
                        { label: 'Distinct Users',  value: abuse.num_distinct_users ?? 0 },
                        { label: 'ISP',             value: abuse.isp || ipapi.isp   || '—' },
                        { label: 'Domain',          value: abuse.domain             || '—' },
                        { label: 'Country',         value: abuse.country_code || ipapi.country_code || '—' },
                        { label: 'Is Tor',          value: abuse.is_tor ? 'Yes' : 'No' },
                      ].map(item => (
                        <div key={item.label} className="bg-slate-800 rounded-lg p-2.5">
                          <div className="text-xs text-slate-500">{item.label}</div>
                          <div className="text-xs text-slate-300 mt-0.5 truncate">{String(item.value)}</div>
                        </div>
                      ))}
                    </div>
                    {abuse.last_reported_at && (
                      <p className="text-xs text-slate-500">
                        Last reported: {new Date(abuse.last_reported_at).toLocaleString()}
                      </p>
                    )}
                  </div>
                )}
              </div>

              {/* ── VirusTotal ── */}
              <div className="space-y-3">
                <div className="flex items-center gap-2">
                  <div className="w-1 h-4 bg-blue-400 rounded-full" />
                  <h3 className="text-sm font-semibold text-slate-200">VirusTotal</h3>
                </div>

                {vt.error === 'no_key' ? (
                  <p className="text-xs text-slate-500">API key not configured.</p>
                ) : vt.error ? (
                  <p className="text-xs text-slate-500">Lookup failed: {vt.error}</p>
                ) : (
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-2">
                      {[
                        { label: 'Malicious',  value: vt.malicious  ?? 0, color: 'text-red-400'    },
                        { label: 'Suspicious', value: vt.suspicious ?? 0, color: 'text-orange-400' },
                        { label: 'Harmless',   value: vt.harmless   ?? 0, color: 'text-green-400'  },
                        { label: 'Undetected', value: vt.undetected ?? 0, color: 'text-slate-400'  },
                      ].map(item => (
                        <div key={item.label} className="bg-slate-800 rounded-lg p-2.5 text-center">
                          <div className={`text-2xl font-bold ${item.color}`}>{item.value}</div>
                          <div className="text-xs text-slate-500 mt-0.5">{item.label}</div>
                        </div>
                      ))}
                    </div>
                    <p className="text-xs text-slate-500">
                      {vt.total_engines ?? 0} engines scanned
                      {vt.last_analysis_date && (
                        <span> · Last scan {new Date(vt.last_analysis_date * 1000).toLocaleDateString()}</span>
                      )}
                    </p>
                    {vt.as_owner && (
                      <p className="text-xs text-slate-500">AS: {vt.as_owner} (ASN {vt.asn})</p>
                    )}
                    {(vt.tags || []).length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {vt.tags.map((t: string) => (
                          <span key={t} className="px-1.5 py-0.5 text-xs bg-slate-700 text-slate-300 rounded">{t}</span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* ── Expandable details ── */}
              <div className="border border-slate-700 rounded-lg overflow-hidden">
                <button
                  onClick={() => setDetailsOpen(o => !o)}
                  className="w-full flex items-center justify-between px-4 py-3 bg-slate-800/60 hover:bg-slate-800 transition-colors text-left"
                >
                  <span className="text-sm font-semibold text-slate-200">Detailed Reports</span>
                  {detailsOpen
                    ? <ChevronDown className="w-4 h-4 text-slate-400 flex-shrink-0" />
                    : <ChevronRight className="w-4 h-4 text-slate-400 flex-shrink-0" />
                  }
                </button>

                {detailsOpen && (
                  <div className="px-4 py-4 space-y-5 bg-slate-900/50">

                    {/* AbuseIPDB categories */}
                    <div className="space-y-2">
                      <p className="text-xs font-semibold text-orange-400 uppercase tracking-wider">AbuseIPDB — Abuse Categories</p>
                      {abuse.error ? (
                        <p className="text-xs text-slate-500">Unavailable</p>
                      ) : (abuse.categories || []).length === 0 ? (
                        <p className="text-xs text-slate-500">No categories reported</p>
                      ) : (
                        <div className="flex flex-wrap gap-1.5">
                          {(abuse.categories as string[]).map(cat => (
                            <span key={cat} className="px-2 py-1 text-xs rounded-md bg-orange-500/10 text-orange-300 border border-orange-500/25">
                              {cat}
                            </span>
                          ))}
                        </div>
                      )}
                      <a
                        href={`https://www.abuseipdb.com/check/${ip}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 mt-1 text-xs text-orange-400 hover:text-orange-300 transition-colors"
                      >
                        <ExternalLink className="w-3 h-3" />
                        View on AbuseIPDB
                      </a>
                    </div>

                    <div className="border-t border-slate-700/60" />

                    {/* VirusTotal vendor verdicts */}
                    <div className="space-y-2">
                      <p className="text-xs font-semibold text-blue-400 uppercase tracking-wider">VirusTotal — Flagged By</p>
                      {vt.error ? (
                        <p className="text-xs text-slate-500">Unavailable</p>
                      ) : (vt.flagged_vendors || []).length === 0 ? (
                        <p className="text-xs text-slate-500">No vendors flagged this IP</p>
                      ) : (
                        <div className="flex flex-wrap gap-1.5">
                          {(vt.flagged_vendors as { name: string; verdict: string }[]).map(v => (
                            <span
                              key={v.name}
                              className={`px-2 py-1 text-xs rounded-md border ${
                                v.verdict === 'malicious'
                                  ? 'bg-red-500/10 text-red-300 border-red-500/25'
                                  : 'bg-orange-500/10 text-orange-300 border-orange-500/25'
                              }`}
                            >
                              {v.name}
                            </span>
                          ))}
                        </div>
                      )}
                      <a
                        href={`https://www.virustotal.com/gui/ip-address/${ip}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1.5 mt-1 text-xs text-blue-400 hover:text-blue-300 transition-colors"
                      >
                        <ExternalLink className="w-3 h-3" />
                        View on VirusTotal
                      </a>
                    </div>

                  </div>
                )}
              </div>

            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-5 py-3 border-t border-slate-800 shrink-0">
          <p className="text-xs text-slate-600">Results cached 1 hour · AbuseIPDB · VirusTotal</p>
        </div>
      </div>
    </>
  );
}
