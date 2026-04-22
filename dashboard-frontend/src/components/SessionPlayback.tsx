import { Terminal, AlertTriangle, Play } from 'lucide-react';
import { useState, useEffect } from 'react';
import { api } from '@/lib/api';

interface SessionPlaybackProps {
  sessionId: string | null;
}

export function SessionPlayback({ sessionId }: SessionPlaybackProps) {
  const [commands, setCommands] = useState<any[]>([]);
  const [isReplaying, setIsReplaying] = useState(false);
  const [replayIndex, setReplayIndex] = useState(0);

  useEffect(() => {
    if (!sessionId) return;
    const fetchCommands = async () => {
      try {
        const res = await api.get(`/api/sessions/${sessionId}/commands`);
        setCommands(res.data.commands || []);
      } catch (err) {
        console.error("Failed to fetch session commands", err);
      }
    };
    fetchCommands();
    const interval = setInterval(fetchCommands, 5000); // refresh every 5s
    return () => clearInterval(interval);
  }, [sessionId]);

  const handleReplay = () => {
    if (commands.length === 0) return;
    setIsReplaying(true);
    setReplayIndex(0);
  };

  useEffect(() => {
    if (isReplaying && replayIndex < commands.length) {
      const timer = setTimeout(() => {
        setReplayIndex(prev => prev + 1);
      }, 1000); // 1 second delay between commands
      return () => clearTimeout(timer);
    } else if (replayIndex >= commands.length) {
      setTimeout(() => setIsReplaying(false), 2000); // stay on final state briefly
    }
  }, [isReplaying, replayIndex, commands.length]);

  const displayedCommands = isReplaying ? commands.slice(0, replayIndex) : commands;

  return (
    <div className="bg-slate-900 rounded-lg border border-slate-800 overflow-hidden flex flex-col">
      <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Terminal className="w-5 h-5 text-green-400" />
          <h2 className="text-slate-100">Session Playback</h2>
          <span className="text-sm text-slate-500">({sessionId || 'No session selected'})</span>
        </div>
        <button
          onClick={handleReplay}
          disabled={isReplaying || commands.length === 0}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-xs transition-colors ${isReplaying || commands.length === 0
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
              : 'bg-slate-800 border border-slate-700 text-slate-300 hover:bg-slate-750'
            }`}
        >
          <Play className={`w-3 h-3 ${isReplaying ? 'animate-pulse text-green-400' : ''}`} />
          {isReplaying ? 'Replaying...' : 'Replay'}
        </button>
      </div>

      <div className="flex-1 overflow-auto p-6 bg-slate-950 font-mono text-sm min-h-[300px]">
        <div className="space-y-2">
          {displayedCommands.map((cmd, idx) => {
            const isSuspicious =
              cmd.command.includes('wget') ||
              cmd.command.includes('cat /etc/') ||
              cmd.command.includes('curl') ||
              cmd.command.includes('chmod') ||
              cmd.command.includes('nmap');
            return (
              <div
                key={idx}
                className={`flex gap-4 p-2 rounded ${isSuspicious ? 'bg-red-500/10 border-l-2 border-red-500' : ''
                  }`}
              >
                <span className="text-slate-500 text-xs shrink-0 pt-1">{new Date(cmd.timestamp).toLocaleTimeString()}</span>
                <div className="flex-1">
                  <div className="flex items-start gap-2">
                    {isSuspicious && (
                      <AlertTriangle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    )}
                    <span className={isSuspicious ? 'text-red-300' : 'text-green-400'}>
                      $ {cmd.command}
                    </span>
                  </div>
                  {isSuspicious && (
                    <div className="mt-1 ml-6 text-xs text-red-400/80">
                      ⚠ Potentially malicious command execution
                    </div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="px-6 py-3 border-t border-slate-800 bg-slate-900 flex items-center justify-between text-xs">
        <span className="text-slate-400">
          <span className="text-white">{commands.length}</span> commands extracted
        </span>
        <span className="text-slate-500">-</span>
      </div>
    </div>
  );
}
