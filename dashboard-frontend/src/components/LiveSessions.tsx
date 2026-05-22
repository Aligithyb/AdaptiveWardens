import { AlertTriangle, Clock, Activity, Wifi, WifiOff, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { api } from '@/lib/api';

interface LiveSessionsProps {
  selectedSession: string | null;
  setSelectedSession: (id: string) => void;
}

export function LiveSessions({ selectedSession, setSelectedSession }: LiveSessionsProps) {
  const [sessions, setSessions] = useState<any[]>([]);

  useEffect(() => {
    const fetchSessions = async () => {
      try {
        const res = await api.get('/api/sessions');
        const fetched = res.data.sessions || [];
        setSessions(fetched);
        if (!selectedSession && fetched.length > 0) {
          setSelectedSession(fetched[0].session_id);
        }
      } catch (err) {
        console.error('Failed to fetch sessions', err);
      }
    };
    fetchSessions();
    const interval = setInterval(fetchSessions, 5000);
    return () => clearInterval(interval);
  }, [selectedSession, setSelectedSession]);

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
      case 'Active':
        return (
          <span className="flex items-center gap-1.5 text-green-400">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
            </span>
            Active
          </span>
        );
      case 'Idle':
        return (
          <span className="flex items-center gap-1.5 text-yellow-400">
            <WifiOff className="w-3 h-3" />
            Idle
          </span>
        );
      case 'Closed':
        return (
          <span className="flex items-center gap-1.5 text-slate-500">
            <XCircle className="w-3 h-3" />
            Closed
          </span>
        );
      default:
        return <span className="text-slate-400">{status}</span>;
    }
  };

  const activeSessions = sessions.filter(s => s.lifecycle_status === 'Active').length;

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-cyan-400" />
          <h2 className="text-slate-100">Live Sessions</h2>
        </div>
        <div className="flex items-center gap-4 text-sm text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-green-400" />
            </span>
            {activeSessions} active
          </span>
          <span>{sessions.length} total</span>
        </div>
      </div>

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
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {sessions.length === 0 ? (
              <tr>
                <td colSpan={8} className="px-6 py-10 text-center text-slate-500 text-sm">
                  No sessions recorded yet. Waiting for connections…
                </td>
              </tr>
            ) : (
              sessions.map((session) => (
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
                  <td className="px-6 py-4 text-sm text-slate-300">{session.source_ip}</td>
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
                  <td className="px-6 py-4 text-sm">
                    {getStatusNode(session.lifecycle_status || 'Active')}
                  </td>
                  <td className="px-6 py-4">
                    <span className={`px-2 py-1 text-xs rounded border ${getRiskStyle(session.risk_level)}`}>
                      {session.risk_level || 'Low'}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
