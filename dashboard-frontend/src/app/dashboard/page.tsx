"use client"

import { useState, useEffect, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import dynamic from 'next/dynamic';
import { Sidebar } from '@/components/Sidebar';
import { Header } from '@/components/Header';
import { LiveSessions } from '@/components/LiveSessions';
import { SessionPlayback } from '@/components/SessionPlayback';
import { IOCSummary } from '@/components/IOCSummary';
import { MitreAttackMap } from '@/components/MitreAttackMap';
import { MetricsStats } from '@/components/MetricsStats';
import { Reports } from '@/components/Reports';
import { ThreatIntelligence } from '@/components/ThreatIntelligence';
import { Lock } from 'lucide-react';
import { SessionUser, canAccess, ROLE_LABELS } from '@/lib/auth';

const AttackHeatmap = dynamic(
  () => import('@/components/AttackHeatmap').then(m => m.AttackHeatmap),
  { ssr: false, loading: () => (
    <div className="bg-slate-900 rounded-xl border border-slate-800 p-8 flex items-center justify-center text-slate-500 text-sm">
      Loading map…
    </div>
  )}
);

export default function DashboardPage() {
  const [activeView, setActiveView] = useState('dashboard');
  const [selectedSession, setSelectedSession] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [user, setUser] = useState<SessionUser | null>(null);
  const [authLoading, setAuthLoading] = useState(true);
  const router = useRouter();

  useEffect(() => {
    fetch('/api/auth/me')
      .then(res => {
        if (!res.ok) { router.replace('/login'); return null; }
        return res.json();
      })
      .then(data => { if (data) setUser(data as SessionUser); })
      .catch(() => router.replace('/login'))
      .finally(() => setAuthLoading(false));
  }, [router]);

  const handleLogout = useCallback(async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    router.replace('/login');
  }, [router]);

  if (authLoading) {
    return (
      <div className="flex h-screen bg-slate-950 items-center justify-center">
        <div className="flex items-center gap-3 text-slate-500">
          <span className="w-5 h-5 border-2 border-slate-700 border-t-cyan-500 rounded-full animate-spin" />
          Loading…
        </div>
      </div>
    );
  }

  if (!user) {
    return (
      <div className="flex h-screen bg-slate-950 items-center justify-center">
        <div className="flex items-center gap-3 text-slate-500">
          <span className="w-5 h-5 border-2 border-slate-700 border-t-cyan-500 rounded-full animate-spin" />
          Redirecting to login…
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-slate-950">
      <Sidebar activeView={activeView} setActiveView={setActiveView} user={user} />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header
          searchQuery={searchQuery}
          onSearchChange={setSearchQuery}
          user={user}
          onLogout={handleLogout}
        />
        <main className="flex-1 overflow-y-auto p-6">
          {!canAccess(user.role, activeView) ? (
            <div className="flex h-full items-center justify-center">
              <div className="text-center max-w-sm">
                <div className="w-16 h-16 bg-red-500/10 border border-red-500/20 rounded-2xl flex items-center justify-center mx-auto mb-5">
                  <Lock className="w-8 h-8 text-red-400" />
                </div>
                <h2 className="text-xl font-semibold text-slate-200 mb-2">Access Restricted</h2>
                <p className="text-sm text-slate-500 mb-4">
                  This section requires elevated privileges. Contact your administrator.
                </p>
                <span className="inline-block px-3 py-1 bg-slate-800 border border-slate-700 rounded-full text-xs text-slate-400">
                  Your role: <span className="text-slate-300 font-medium">{ROLE_LABELS[user.role]}</span>
                </span>
              </div>
            </div>
          ) : (
            <>
              {activeView === 'dashboard' && (
                <div className="space-y-6">
                  <MetricsStats />
                  <AttackHeatmap />
                  <LiveSessions selectedSession={selectedSession} setSelectedSession={setSelectedSession} />
                  <SessionPlayback sessionId={selectedSession} />
                  <IOCSummary />
                  <MitreAttackMap />
                </div>
              )}
              {activeView === 'live-sessions' && (
                <div className="space-y-6">
                  <LiveSessions selectedSession={selectedSession} setSelectedSession={setSelectedSession} />
                  <SessionPlayback sessionId={selectedSession} />
                </div>
              )}
              {activeView === 'ioc-summary' && <IOCSummary />}
              {activeView === 'attack-map' && <AttackHeatmap />}
              {activeView === 'mitre-attack' && <MitreAttackMap />}
              {activeView === 'metrics' && <MetricsStats />}
              {activeView === 'reports' && <Reports />}
              {activeView === 'threat-intelligence' && <ThreatIntelligence />}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
