import { AlertTriangle, Clock, Activity } from 'lucide-react';
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
        const fetchedSessions = res.data.sessions || [];
        setSessions(fetchedSessions);

        // Auto-select the first (latest) session if none is selected
        if (!selectedSession && fetchedSessions.length > 0) {
          setSelectedSession(fetchedSessions[0].session_id);
        }
      } catch (err) {
        console.error("Failed to fetch sessions", err);
      }
    };
    fetchSessions();
    const interval = setInterval(fetchSessions, 5000); // refresh every 5s
    return () => clearInterval(interval);
  }, [selectedSession, setSelectedSession]);

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'Critical': return 'text-red-400 bg-red-500/10 border-red-500/30';
      case 'High': return 'text-orange-400 bg-orange-500/10 border-orange-500/30';
      case 'Medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
      case 'Low': return 'text-blue-400 bg-blue-500/10 border-blue-500/30';
      default: return 'text-slate-400 bg-slate-500/10 border-slate-500/30';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Active': return 'text-green-400';
      case 'Monitoring': return 'text-yellow-400';
      case 'Terminated': return 'text-slate-500';
      default: return 'text-slate-400';
    }
  };

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden">
      <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-cyan-400" />
          <h2 className="text-slate-100">Live Sessions</h2>
        </div>
        <span className="text-sm text-slate-400">{sessions.length} sessions</span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full">
          <thead className="bg-slate-800/50">
            <tr>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Session ID</th>
              <th className="px-6 py-3 text-left text-xs text-slate-400">IP Address</th>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Type</th>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Start Time</th>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Status</th>
              <th className="px-6 py-3 text-left text-xs text-slate-400">Risk Level</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {sessions.map((session) => (
              <tr
                key={session.session_id}
                onClick={() => setSelectedSession(session.session_id)}
                className={`hover:bg-slate-800/50 transition-colors cursor-pointer ${selectedSession === session.session_id ? 'bg-cyan-500/5 border-l-2 border-cyan-500' : ''
                  }`}
              >
                <td className="px-6 py-4 text-sm text-cyan-400">{session.session_id}</td>
                <td className="px-6 py-4 text-sm text-slate-300">{session.source_ip}</td>
                <td className="px-6 py-4">
                  <span className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded uppercase">
                    {session.protocol}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-slate-400 flex items-center gap-2">
                  <Clock className="w-3 h-3" />
                  {new Date(session.start_time).toLocaleTimeString()}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span className={getStatusColor('Active')}>Active</span>
                </td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 text-xs rounded border ${getRiskColor('High')}`}>
                    High
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
