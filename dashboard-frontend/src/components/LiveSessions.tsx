import { AlertTriangle, Clock, Activity } from 'lucide-react';

interface LiveSessionsProps {
  selectedSession: string;
  setSelectedSession: (id: string) => void;
}

export function LiveSessions({ selectedSession, setSelectedSession }: LiveSessionsProps) {
  const sessions = [
    { id: 'sess-7f8a9b2c', ip: '45.142.212.61', type: 'SSH', startTime: '14:23:41', status: 'Active', riskLevel: 'High' },
    { id: 'sess-3c4d5e6f', ip: '103.75.189.44', type: 'HTTP', startTime: '14:18:12', status: 'Active', riskLevel: 'Critical' },
    { id: 'sess-9a8b7c6d', ip: '185.220.101.33', type: 'FTP', startTime: '14:15:08', status: 'Monitoring', riskLevel: 'Medium' },
    { id: 'sess-1e2f3a4b', ip: '192.168.1.105', type: 'SMB', startTime: '14:12:55', status: 'Active', riskLevel: 'Low' },
    { id: 'sess-5d6e7f8a', ip: '210.45.78.92', type: 'SSH', startTime: '14:10:33', status: 'Terminated', riskLevel: 'High' },
    { id: 'sess-2b3c4d5e', ip: '157.90.123.78', type: 'Telnet', startTime: '14:08:19', status: 'Active', riskLevel: 'Medium' },
  ];

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
        <span className="text-sm text-slate-400">{sessions.filter(s => s.status === 'Active').length} active</span>
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
                key={session.id}
                onClick={() => setSelectedSession(session.id)}
                className={`hover:bg-slate-800/50 transition-colors cursor-pointer ${
                  selectedSession === session.id ? 'bg-cyan-500/5 border-l-2 border-cyan-500' : ''
                }`}
              >
                <td className="px-6 py-4 text-sm text-cyan-400">{session.id}</td>
                <td className="px-6 py-4 text-sm text-slate-300">{session.ip}</td>
                <td className="px-6 py-4">
                  <span className="px-2 py-1 text-xs bg-slate-800 text-slate-300 rounded">
                    {session.type}
                  </span>
                </td>
                <td className="px-6 py-4 text-sm text-slate-400 flex items-center gap-2">
                  <Clock className="w-3 h-3" />
                  {session.startTime}
                </td>
                <td className="px-6 py-4 text-sm">
                  <span className={getStatusColor(session.status)}>{session.status}</span>
                </td>
                <td className="px-6 py-4">
                  <span className={`px-2 py-1 text-xs rounded border ${getRiskColor(session.riskLevel)}`}>
                    {session.riskLevel}
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
