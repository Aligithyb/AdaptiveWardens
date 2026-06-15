"use client"

import { FileText, Download, Printer, Search, Filter, Sparkles, X, ChevronDown, ChevronRight } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8003';

function getRiskStyle(level: string) {
  switch (level) {
    case 'Critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
    case 'High':     return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
    case 'Medium':   return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
    case 'Low':      return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
    default:         return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
  }
}

function fmtDuration(seconds: number | null) {
  if (!seconds) return '—';
  if (seconds < 60) return `${seconds}s`;
  const m = Math.floor(seconds / 60);
  const s = seconds % 60;
  return `${m}m ${s}s`;
}

function generatePrintHTML(session: any, detail: any, aiReport?: any): string {
  const commands = detail.commands || [];
  const techniques = detail.techniques || [];
  const iocs = detail.iocs || [];

  const cmdRows = commands.map((c: any) => `
    <tr>
      <td>${c.sequence_number}</td>
      <td>${c.timestamp ?? ''}</td>
      <td><code>${(c.command ?? '').replace(/</g, '&lt;')}</code></td>
      <td>${c.exit_code ?? 0}</td>
    </tr>`).join('');

  const techRows = techniques.map((t: any) => `
    <tr>
      <td>${t.technique_id}</td>
      <td>${t.technique_name ?? ''}</td>
      <td>${t.tactic ?? ''}</td>
      <td>${Math.round((t.confidence ?? 0) * 100)}%</td>
    </tr>`).join('');

  const iocRows = iocs.map((i: any) => `
    <tr>
      <td>${i.ioc_type}</td>
      <td><code>${(i.value ?? '').replace(/</g, '&lt;')}</code></td>
      <td>${Math.round((i.confidence ?? 0) * 100)}%</td>
    </tr>`).join('');

  // AI report section — prepended when available
  let aiSection = '';
  if (aiReport) {
    const killChainRows = (aiReport.kill_chain || []).map((kc: any) => `
      <tr>
        <td><strong>${kc.tactic ?? ''}</strong></td>
        <td>${(kc.techniques || []).join(', ')}</td>
        <td>${kc.summary ?? ''}</td>
      </tr>`).join('');

    const iocNotableRows = (aiReport.notable_iocs || []).map((i: any) => `
      <tr>
        <td>${i.type ?? ''}</td>
        <td><code>${(i.value ?? '').replace(/</g, '&lt;')}</code></td>
        <td>${i.significance ?? ''}</td>
      </tr>`).join('');

    const actionItems = (aiReport.recommended_actions || [])
      .map((a: string) => `<li>${a}</li>`).join('');

    const badge = aiReport.source === 'ai'
      ? '<span style="background:#d1fae5;color:#065f46;padding:2px 8px;border-radius:4px;font-size:10px">AI Generated</span>'
      : '<span style="background:#fef3c7;color:#92400e;padding:2px 8px;border-radius:4px;font-size:10px">Template (AI unavailable)</span>';

    aiSection = `
  <div style="background:#f0fdf4;border:1px solid #86efac;border-radius:6px;padding:16px;margin-bottom:24px">
    <h2 style="color:#15803d;border-bottom:2px solid #86efac;padding-bottom:6px;margin:0 0 12px">
      Analyst Summary (AI) ${badge}
    </h2>

    <h3 style="font-size:13px;color:#334155;margin:12px 0 4px">Executive Summary</h3>
    <p style="margin:0 0 12px;line-height:1.5">${aiReport.executive_summary ?? ''}</p>

    <h3 style="font-size:13px;color:#334155;margin:12px 0 4px">Attacker Objective</h3>
    <p style="margin:0 0 12px;line-height:1.5">${aiReport.attacker_objective ?? ''}</p>

    <h3 style="font-size:13px;color:#334155;margin:12px 0 4px">Kill Chain</h3>
    ${killChainRows ? `<table style="border-collapse:collapse;width:100%;margin-bottom:12px">
      <thead><tr><th style="background:#dcfce7;padding:6px 10px;text-align:left;font-size:11px">Tactic</th><th style="background:#dcfce7;padding:6px 10px;text-align:left;font-size:11px">Techniques</th><th style="background:#dcfce7;padding:6px 10px;text-align:left;font-size:11px">Summary</th></tr></thead>
      <tbody>${killChainRows}</tbody></table>` : '<p style="color:#94a3b8;margin:0 0 12px">No kill chain data.</p>'}

    <h3 style="font-size:13px;color:#334155;margin:12px 0 4px">Notable IOCs</h3>
    ${iocNotableRows ? `<table style="border-collapse:collapse;width:100%;margin-bottom:12px">
      <thead><tr><th style="background:#dcfce7;padding:6px 10px;text-align:left;font-size:11px">Type</th><th style="background:#dcfce7;padding:6px 10px;text-align:left;font-size:11px">Value</th><th style="background:#dcfce7;padding:6px 10px;text-align:left;font-size:11px">Significance</th></tr></thead>
      <tbody>${iocNotableRows}</tbody></table>` : '<p style="color:#94a3b8;margin:0 0 12px">No notable IOCs.</p>'}

    <h3 style="font-size:13px;color:#334155;margin:12px 0 4px">Severity Justification</h3>
    <p style="margin:0 0 12px;line-height:1.5">${aiReport.severity_justification ?? ''}</p>

    <h3 style="font-size:13px;color:#334155;margin:12px 0 4px">Recommended Actions</h3>
    ${actionItems ? `<ul style="margin:0 0 12px;padding-left:20px;line-height:1.8">${actionItems}</ul>` : '<p style="color:#94a3b8;margin:0">None.</p>'}
  </div>`;
  }

  return `<!DOCTYPE html>
<html>
<head>
  <title>Session Report — ${session.session_id?.slice(0, 8)}</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: 'Segoe UI', Arial, sans-serif; padding: 32px; color: #1a1a2e; font-size: 13px; }
    h1 { color: #0891b2; margin: 0 0 4px; font-size: 22px; }
    .subtitle { color: #64748b; margin-bottom: 24px; font-size: 12px; }
    h2 { font-size: 15px; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; margin: 24px 0 10px; color: #334155; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 16px; }
    th { background: #f1f5f9; color: #475569; text-align: left; padding: 7px 10px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.05em; }
    td { padding: 7px 10px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    code { font-family: monospace; font-size: 12px; background: #f8fafc; padding: 1px 4px; border-radius: 3px; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
    .Critical { background: #fee2e2; color: #dc2626; }
    .High { background: #ffedd5; color: #ea580c; }
    .Medium { background: #fefce8; color: #ca8a04; }
    .Low { background: #eff6ff; color: #2563eb; }
    .footer { margin-top: 40px; padding-top: 12px; border-top: 1px solid #e2e8f0; color: #94a3b8; font-size: 11px; }
    @media print { body { padding: 16px; } }
  </style>
</head>
<body>
  <h1>AdaptiveWardens — Session Report</h1>
  <p class="subtitle">Generated ${new Date().toUTCString()}</p>

  ${aiSection}

  <h2>Session Overview</h2>
  <table>
    <tr><th>Session ID</th><td><code>${session.session_id}</code></td>
        <th>Risk Level</th><td><span class="badge ${session.risk_level}">${session.risk_level ?? '—'}</span></td></tr>
    <tr><th>Source IP</th><td>${session.source_ip ?? '—'}</td>
        <th>Country</th><td>${session.country ?? 'Unknown'}</td></tr>
    <tr><th>Protocol</th><td>${(session.protocol ?? '').toUpperCase()}</td>
        <th>Status</th><td>${session.lifecycle_status ?? session.status ?? '—'}</td></tr>
    <tr><th>Start Time</th><td>${session.start_time ?? '—'}</td>
        <th>End Time</th><td>${session.end_time ?? 'Still active'}</td></tr>
    <tr><th>Commands Run</th><td>${commands.length}</td>
        <th>MITRE Techniques</th><td>${techniques.length}</td></tr>
  </table>

  <h2>Command History (${commands.length})</h2>
  ${commands.length === 0 ? '<p style="color:#94a3b8">No commands recorded.</p>' : `
  <table>
    <thead><tr><th>#</th><th>Timestamp</th><th>Command</th><th>Exit</th></tr></thead>
    <tbody>${cmdRows}</tbody>
  </table>`}

  <h2>MITRE ATT&CK Techniques (${techniques.length})</h2>
  ${techniques.length === 0 ? '<p style="color:#94a3b8">No techniques detected.</p>' : `
  <table>
    <thead><tr><th>ID</th><th>Name</th><th>Tactic</th><th>Confidence</th></tr></thead>
    <tbody>${techRows}</tbody>
  </table>`}

  <h2>Indicators of Compromise (${iocs.length})</h2>
  ${iocs.length === 0 ? '<p style="color:#94a3b8">No IOCs recorded.</p>' : `
  <table>
    <thead><tr><th>Type</th><th>Value</th><th>Confidence</th></tr></thead>
    <tbody>${iocRows}</tbody>
  </table>`}

  <div class="footer">AdaptiveWardens SOC Platform — NexoPay Honeypot Infrastructure</div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// AI Report Modal
// ---------------------------------------------------------------------------

function KillChainItem({ item }: { item: any }) {
  const [open, setOpen] = useState(true);
  return (
    <div className="border border-slate-700 rounded-lg overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-2 bg-slate-800 hover:bg-slate-700 transition-colors text-left"
      >
        <span className="text-sm font-medium text-cyan-300">{item.tactic}</span>
        {open ? <ChevronDown className="w-4 h-4 text-slate-400" /> : <ChevronRight className="w-4 h-4 text-slate-400" />}
      </button>
      {open && (
        <div className="px-4 py-3 space-y-1">
          <div className="flex flex-wrap gap-1 mb-2">
            {(item.techniques || []).map((t: string, i: number) => (
              <span key={i} className="px-2 py-0.5 text-xs bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 rounded">
                {t}
              </span>
            ))}
          </div>
          <p className="text-sm text-slate-300">{item.summary}</p>
        </div>
      )}
    </div>
  );
}

function AIReportModal({
  session,
  detail,
  aiData,
  onClose,
}: {
  session: any;
  detail: any;
  aiData: { report: any; cached: boolean; generated_at: string | null };
  onClose: () => void;
}) {
  const report = aiData.report;

  const handlePrintWithAI = async () => {
    const html = generatePrintHTML(session, detail, report);
    const win = window.open('', '_blank');
    if (win) {
      win.document.write(html);
      win.document.close();
      setTimeout(() => win.print(), 500);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <Sparkles className="w-5 h-5 text-cyan-400" />
            <h2 className="text-slate-100 font-semibold">AI Incident Report</h2>
            <span className="text-xs text-slate-500 font-mono">
              {session.session_id?.slice(0, 8)}
            </span>
            {report.source === 'ai' ? (
              <span className="px-2 py-0.5 text-xs bg-green-500/10 border border-green-500/20 text-green-400 rounded">
                AI Generated
              </span>
            ) : (
              <span className="px-2 py-0.5 text-xs bg-yellow-500/10 border border-yellow-500/20 text-yellow-400 rounded">
                Template
              </span>
            )}
            {aiData.cached && (
              <span className="px-2 py-0.5 text-xs bg-slate-700 text-slate-400 rounded">cached</span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handlePrintWithAI}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-slate-800 border border-slate-700 text-slate-300 hover:text-orange-400 hover:border-orange-500/30 rounded-lg transition-colors"
            >
              <Printer className="w-3.5 h-3.5" />
              Save as PDF
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-6 py-4 space-y-6">
          {/* Executive Summary */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Executive Summary
            </h3>
            <p className="text-sm text-slate-300 leading-relaxed">{report.executive_summary}</p>
          </section>

          {/* Attacker Objective */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Attacker Objective
            </h3>
            <p className="text-sm text-slate-300 leading-relaxed">{report.attacker_objective}</p>
          </section>

          {/* Kill Chain */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
              Kill Chain
            </h3>
            <div className="space-y-2">
              {(report.kill_chain || []).length === 0 ? (
                <p className="text-sm text-slate-500">No kill chain data.</p>
              ) : (
                (report.kill_chain || []).map((kc: any, i: number) => (
                  <KillChainItem key={i} item={kc} />
                ))
              )}
            </div>
          </section>

          {/* Notable IOCs */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
              Notable IOCs
            </h3>
            {(report.notable_iocs || []).length === 0 ? (
              <p className="text-sm text-slate-500">No notable IOCs.</p>
            ) : (
              <div className="space-y-2">
                {(report.notable_iocs || []).map((ioc: any, i: number) => (
                  <div key={i} className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700">
                    <span className="px-2 py-0.5 text-xs bg-slate-700 text-slate-300 rounded font-mono shrink-0">
                      {ioc.type}
                    </span>
                    <div>
                      <p className="text-sm font-mono text-amber-300">{ioc.value}</p>
                      <p className="text-xs text-slate-400 mt-0.5">{ioc.significance}</p>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {/* Severity Justification */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
              Severity Justification
            </h3>
            <div className="p-3 bg-slate-800/50 border border-slate-700 rounded-lg">
              <p className="text-sm text-slate-300 leading-relaxed">{report.severity_justification}</p>
            </div>
          </section>

          {/* Recommended Actions */}
          <section>
            <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
              Recommended Actions
            </h3>
            {(report.recommended_actions || []).length === 0 ? (
              <p className="text-sm text-slate-500">No recommendations.</p>
            ) : (
              <ol className="space-y-2">
                {(report.recommended_actions || []).map((action: string, i: number) => (
                  <li key={i} className="flex items-start gap-3">
                    <span className="shrink-0 w-5 h-5 flex items-center justify-center rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-bold">
                      {i + 1}
                    </span>
                    <p className="text-sm text-slate-300 leading-relaxed">{action}</p>
                  </li>
                ))}
              </ol>
            )}
          </section>

          {aiData.generated_at && (
            <p className="text-xs text-slate-600 text-right">
              Generated {new Date(aiData.generated_at).toLocaleString()}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Reports component
// ---------------------------------------------------------------------------

export function Reports() {
  const [sessions, setSessions] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState('All');
  const [exporting, setExporting] = useState<string | null>(null);

  // AI report modal state
  const [aiModal, setAiModal] = useState<{
    session: any;
    detail: any;
    aiData: { report: any; cached: boolean; generated_at: string | null };
  } | null>(null);

  useEffect(() => {
    const fetch = async () => {
      try {
        const res = await api.get('/api/reports');
        setSessions(res.data.sessions || []);
      } catch (err) {
        console.error('Failed to fetch reports', err);
      } finally {
        setLoading(false);
      }
    };
    fetch();
    const interval = setInterval(fetch, 15000);
    return () => clearInterval(interval);
  }, []);

  const filtered = sessions.filter(s => {
    const matchSearch =
      !search ||
      s.source_ip?.includes(search) ||
      s.session_id?.includes(search) ||
      s.country?.toLowerCase().includes(search.toLowerCase());
    const matchRisk = riskFilter === 'All' || s.risk_level === riskFilter;
    return matchSearch && matchRisk;
  });

  const exportJSON = async (sessionId: string) => {
    setExporting(sessionId + '-json');
    try {
      window.open(`${API_BASE}/api/reports/${sessionId}/json`, '_blank');
    } finally {
      setExporting(null);
    }
  };

  const exportCSV = async (sessionId: string) => {
    setExporting(sessionId + '-csv');
    try {
      window.open(`${API_BASE}/api/reports/${sessionId}/csv`, '_blank');
    } finally {
      setExporting(null);
    }
  };

  const printPDF = async (session: any) => {
    setExporting(session.session_id + '-pdf');
    try {
      const res = await api.get(`/api/sessions/${session.session_id}`);
      const html = generatePrintHTML(session, res.data);
      const win = window.open('', '_blank');
      if (win) {
        win.document.write(html);
        win.document.close();
        setTimeout(() => win.print(), 500);
      }
    } catch (err) {
      console.error('Print failed', err);
    } finally {
      setExporting(null);
    }
  };

  const openAIReport = async (session: any) => {
    setExporting(session.session_id + '-ai');
    try {
      // Fetch session detail and AI summary in parallel
      const [detailRes, aiRes] = await Promise.all([
        api.get(`/api/sessions/${session.session_id}`),
        api.get(`/api/reports/${session.session_id}/ai-summary`, { timeout: 35000 }),
      ]);
      setAiModal({
        session,
        detail: detailRes.data,
        aiData: aiRes.data,
      });
    } catch (err) {
      console.error('AI report failed', err);
    } finally {
      setExporting(null);
    }
  };

  const riskLevels = ['All', 'Critical', 'High', 'Medium', 'Low'];

  const summary = {
    total: sessions.length,
    critical: sessions.filter(s => s.risk_level === 'Critical').length,
    high: sessions.filter(s => s.risk_level === 'High').length,
    active: sessions.filter(s => s.lifecycle_status === 'Active').length,
  };

  return (
    <>
      {aiModal && (
        <AIReportModal
          session={aiModal.session}
          detail={aiModal.detail}
          aiData={aiModal.aiData}
          onClose={() => setAiModal(null)}
        />
      )}

      <div className="space-y-6">
        {/* Summary cards */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total Sessions', value: summary.total, color: 'cyan' },
            { label: 'Critical Risk', value: summary.critical, color: 'red' },
            { label: 'High Risk', value: summary.high, color: 'orange' },
            { label: 'Active Now', value: summary.active, color: 'green' },
          ].map(card => (
            <div key={card.label} className={`bg-slate-900 border border-${card.color}-500/20 rounded-lg p-4`}>
              <div className={`text-2xl text-${card.color}-400 mb-1`}>{card.value}</div>
              <div className="text-xs text-slate-500">{card.label}</div>
            </div>
          ))}
        </div>

        {/* Main table */}
        <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between gap-4 flex-wrap">
            <div className="flex items-center gap-3">
              <FileText className="w-5 h-5 text-cyan-400" />
              <h2 className="text-slate-100">Session Reports</h2>
              <span className="text-sm text-slate-500">{filtered.length} sessions</span>
            </div>

            <div className="flex items-center gap-3">
              <div className="relative">
                <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  placeholder="Search IP, country, session…"
                  value={search}
                  onChange={e => setSearch(e.target.value)}
                  className="bg-slate-800 border border-slate-700 text-slate-300 text-sm rounded-lg pl-9 pr-4 py-2 w-56 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-slate-400" />
                {riskLevels.map(r => (
                  <button
                    key={r}
                    onClick={() => setRiskFilter(r)}
                    className={`px-3 py-1.5 text-xs rounded-lg border transition-colors ${
                      riskFilter === r
                        ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                        : 'border-slate-700 text-slate-400 hover:border-slate-600'
                    }`}
                  >
                    {r}
                  </button>
                ))}
              </div>
            </div>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-slate-800/50">
                <tr>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Session</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">IP / Country</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Protocol</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Start Time</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Duration</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Cmds</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Techniques</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Status</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Risk</th>
                  <th className="px-6 py-3 text-left text-xs text-slate-400">Export</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {loading ? (
                  <tr>
                    <td colSpan={10} className="px-6 py-10 text-center text-slate-500 text-sm">
                      Loading sessions…
                    </td>
                  </tr>
                ) : filtered.length === 0 ? (
                  <tr>
                    <td colSpan={10} className="px-6 py-10 text-center text-slate-500 text-sm">
                      No sessions match your filters.
                    </td>
                  </tr>
                ) : (
                  filtered.map(session => (
                    <tr key={session.session_id} className="hover:bg-slate-800/30 transition-colors">
                      <td className="px-6 py-4 text-sm font-mono text-cyan-400">
                        {session.session_id?.slice(0, 8)}…
                      </td>
                      <td className="px-6 py-4">
                        <div className="text-sm text-slate-300">{session.source_ip}</div>
                        <div className="text-xs text-slate-500">{session.country || 'Unknown'}</div>
                      </td>
                      <td className="px-6 py-4">
                        <span className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded uppercase">
                          {session.protocol}
                        </span>
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-400">
                        {new Date(session.start_time).toLocaleString()}
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-400">
                        {fmtDuration(session.duration_seconds)}
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-400">
                        {session.command_count ?? 0}
                      </td>
                      <td className="px-6 py-4 text-sm text-slate-400">
                        {session.technique_count ?? 0}
                      </td>
                      <td className="px-6 py-4 text-sm">
                        <span className={
                          session.lifecycle_status === 'Active' ? 'text-green-400' :
                          session.lifecycle_status === 'Idle' ? 'text-yellow-400' :
                          'text-slate-500'
                        }>
                          {session.lifecycle_status ?? session.status}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-2 py-1 text-xs rounded border ${getRiskStyle(session.risk_level)}`}>
                          {session.risk_level ?? 'Low'}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => exportJSON(session.session_id)}
                            disabled={exporting === session.session_id + '-json'}
                            title="Download JSON"
                            className="p-1.5 rounded text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors disabled:opacity-50"
                          >
                            <Download className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => exportCSV(session.session_id)}
                            disabled={exporting === session.session_id + '-csv'}
                            title="Download CSV"
                            className="p-1.5 rounded text-slate-400 hover:text-green-400 hover:bg-slate-800 transition-colors disabled:opacity-50 text-xs font-mono"
                          >
                            CSV
                          </button>
                          <button
                            onClick={() => printPDF(session)}
                            disabled={exporting === session.session_id + '-pdf'}
                            title="Print / Save as PDF"
                            className="p-1.5 rounded text-slate-400 hover:text-orange-400 hover:bg-slate-800 transition-colors disabled:opacity-50"
                          >
                            <Printer className="w-4 h-4" />
                          </button>
                          <button
                            onClick={() => openAIReport(session)}
                            disabled={exporting === session.session_id + '-ai'}
                            title="AI Incident Report"
                            className="p-1.5 rounded text-slate-400 hover:text-cyan-300 hover:bg-slate-800 transition-colors disabled:opacity-50"
                          >
                            {exporting === session.session_id + '-ai' ? (
                              <span className="text-xs text-slate-500 animate-pulse">…</span>
                            ) : (
                              <Sparkles className="w-4 h-4" />
                            )}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
