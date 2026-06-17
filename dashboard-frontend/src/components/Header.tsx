"use client"

import { Search, Bell, LogOut, Sun, Moon, ShieldAlert, AlertTriangle, X } from 'lucide-react';
import { useTheme } from 'next-themes';
import { useEffect, useState, useRef } from 'react';
import { api } from '@/lib/api';
import { SessionUser, ROLE_LABELS, ROLE_COLORS } from '@/lib/auth';

interface AlertSession {
  session_id: string;
  source_ip: string;
  country: string;
  risk_level: string;
  threat_score: number;
  start_time: string;
  lifecycle_status: string;
}

interface HeaderProps {
  searchQuery?: string;
  onSearchChange?: (q: string) => void;
  user?: SessionUser | null;
  onLogout?: () => void;
}

export function Header({ searchQuery = '', onSearchChange, user, onLogout }: HeaderProps) {
  const role = user?.role;
  const colors = role ? ROLE_COLORS[role] : null;
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  const [showAlerts, setShowAlerts] = useState(false);
  const [alerts, setAlerts] = useState<AlertSession[]>([]);
  const panelRef = useRef<HTMLDivElement>(null);

  // Avoid hydration mismatch — only render theme icon after mount
  useEffect(() => setMounted(true), []);

  // Fetch high-risk sessions for the notification panel
  useEffect(() => {
    const load = async () => {
      try {
        const res = await api.get('/api/sessions?limit=50');
        const sessions: AlertSession[] = (res.data.sessions || []).filter(
          (s: AlertSession) => s.risk_level === 'Critical' || s.risk_level === 'High'
        );
        setAlerts(sessions.slice(0, 10));
      } catch { /* non-fatal */ }
    };
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);

  // Close panel on outside click
  useEffect(() => {
    if (!showAlerts) return;
    const handler = (e: MouseEvent) => {
      if (panelRef.current && !panelRef.current.contains(e.target as Node)) {
        setShowAlerts(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [showAlerts]);

  const riskColor = (level: string) =>
    level === 'Critical' ? 'text-red-400' : 'text-orange-400';

  const criticalCount = alerts.filter(a => a.risk_level === 'Critical').length;

  return (
    <header className="bg-slate-900 border-b border-slate-800 px-6 py-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4 flex-1">
          <div className="relative flex-1 max-w-md">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-5 h-5 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={e => onSearchChange?.(e.target.value)}
              placeholder="Search sessions, IPs, IOCs..."
              className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          </div>
        </div>

        <div className="flex items-center gap-2 ml-6">
          {/* Theme toggle */}
          {mounted && (
            <button
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              className="p-2 rounded-lg text-slate-400 hover:text-yellow-400 hover:bg-yellow-500/10 transition-colors"
            >
              {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>
          )}

          {/* Notification bell + panel */}
          <div className="relative" ref={panelRef}>
            <button
              onClick={() => setShowAlerts(o => !o)}
              className="relative p-2 text-slate-400 hover:text-slate-200 hover:bg-slate-800 rounded-lg transition-colors"
              title="Alerts"
            >
              <Bell className="w-5 h-5" />
              {alerts.length > 0 && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full ring-2 ring-slate-900 animate-pulse" />
              )}
            </button>

            {showAlerts && (
              <div className="absolute right-0 top-full mt-2 w-80 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl z-50 overflow-hidden">
                <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-red-400" />
                    <span className="text-sm font-medium text-slate-200">High-Risk Alerts</span>
                    {criticalCount > 0 && (
                      <span className="px-1.5 py-0.5 text-xs bg-red-500/20 text-red-400 rounded font-bold">
                        {criticalCount} critical
                      </span>
                    )}
                  </div>
                  <button onClick={() => setShowAlerts(false)} className="p-1 rounded text-slate-500 hover:text-slate-300">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
                <div className="max-h-72 overflow-y-auto">
                  {alerts.length === 0 ? (
                    <div className="px-4 py-6 text-center text-slate-500 text-sm">
                      No high-risk sessions
                    </div>
                  ) : (
                    alerts.map(a => (
                      <div
                        key={a.session_id}
                        className="flex items-start gap-3 px-4 py-3 border-b border-slate-800/60 hover:bg-slate-800/40 transition-colors"
                      >
                        <AlertTriangle className={`w-4 h-4 mt-0.5 shrink-0 ${riskColor(a.risk_level)}`} />
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-xs text-cyan-400">{a.source_ip}</span>
                            <span className={`text-xs font-bold ${riskColor(a.risk_level)}`}>{a.risk_level}</span>
                          </div>
                          <div className="text-xs text-slate-500 mt-0.5">
                            {a.country || 'Unknown'} · Score {a.threat_score}
                          </div>
                          <div className="text-xs text-slate-600">
                            {new Date(a.start_time).toLocaleString()}
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
                {alerts.length > 0 && (
                  <div className="px-4 py-2 text-xs text-slate-600 border-t border-slate-800">
                    Showing {alerts.length} high/critical sessions · refreshes every 30s
                  </div>
                )}
              </div>
            )}
          </div>

          {/* User info */}
          <div className="flex items-center gap-3 pl-2 border-l border-slate-800">
            <div className="w-8 h-8 bg-gradient-to-br from-purple-500 to-pink-600 rounded-full flex items-center justify-center text-xs font-bold text-white shadow-sm">
              {user ? user.fullName.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase() : 'U'}
            </div>
            <div className="text-sm">
              <div className="text-slate-200 font-medium leading-tight">{user?.fullName ?? 'Loading...'}</div>
              {role && colors ? (
                <span className={`text-xs font-medium ${colors.text}`}>
                  {ROLE_LABELS[role]}
                </span>
              ) : (
                <div className="text-xs text-slate-500">SOC Team</div>
              )}
            </div>
          </div>

          {/* Logout */}
          {onLogout && (
            <button
              onClick={onLogout}
              title="Sign out"
              className="p-2 text-slate-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
            >
              <LogOut className="w-5 h-5" />
            </button>
          )}
        </div>
      </div>
    </header>
  );
}
