"use client"

import { useState } from 'react';
import dynamic from 'next/dynamic';
import { Sidebar } from '@/components/Sidebar';
import { Header } from '@/components/Header';
import { LiveSessions } from '@/components/LiveSessions';
import { SessionPlayback } from '@/components/SessionPlayback';
import { IOCSummary } from '@/components/IOCSummary';
import { MitreAttackMap } from '@/components/MitreAttackMap';
import { MetricsStats } from '@/components/MetricsStats';

const AttackHeatmap = dynamic(
  () => import('@/components/AttackHeatmap').then(m => m.AttackHeatmap),
  { ssr: false, loading: () => (
    <div className="bg-slate-900 rounded-xl border border-slate-800 p-8 flex items-center justify-center text-slate-500 text-sm">
      Loading map…
    </div>
  )}
);

export default function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [selectedSession, setSelectedSession] = useState<string | null>(null);

  return (
    <div className="flex h-screen bg-slate-950">
      <Sidebar activeView={activeView} setActiveView={setActiveView} />
      <div className="flex-1 flex flex-col overflow-hidden">
        <Header />
        <main className="flex-1 overflow-y-auto p-6">
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
          {activeView === 'reports' && (
            <div className="bg-slate-900 rounded-lg border border-slate-800 p-6 text-slate-400">
              Reports coming soon...
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
