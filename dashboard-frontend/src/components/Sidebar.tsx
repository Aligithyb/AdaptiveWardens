import { Activity, Shield, Map, BarChart3, FileText, Layers, Globe2, ShieldAlert, Lock, ShieldCheck, Bug } from 'lucide-react';
import { SessionUser, canAccess } from '@/lib/auth';

interface SidebarProps {
  activeView: string;
  setActiveView: (view: string) => void;
  user?: SessionUser | null;
}

export function Sidebar({ activeView, setActiveView, user }: SidebarProps) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: Layers },
    { id: 'live-sessions', label: 'Live Sessions', icon: Activity },
    { id: 'attack-map', label: 'Attack Map', icon: Globe2 },
    { id: 'ioc-summary', label: 'IOC Summary', icon: Shield },
    { id: 'mitre-attack', label: 'MITRE ATT&CK', icon: Map },
    { id: 'metrics', label: 'Session Metrics', icon: BarChart3 },
    { id: 'reports', label: 'Reports', icon: FileText },
    { id: 'threat-intelligence', label: 'Threat Intel', icon: ShieldAlert },
    { id: 'malware-analysis', label: 'Malware Analysis', icon: Bug },
    { id: 'effectiveness', label: 'Effectiveness', icon: ShieldCheck },
  ];

  return (
    <div className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col">
      <div className="p-6 border-b border-slate-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-gradient-to-br from-cyan-500 to-blue-600 rounded-lg flex items-center justify-center">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="text-slate-100">AdaptiveWardens</h1>
            <p className="text-xs text-slate-500">SOC Platform</p>
          </div>
        </div>
      </div>

      <nav className="flex-1 p-4">
        <ul className="space-y-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const locked = user ? !canAccess(user.role, item.id) : false;
            return (
              <li key={item.id}>
                <button
                  onClick={() => setActiveView(item.id)}
                  className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg transition-colors ${
                    activeView === item.id
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
                      : 'text-slate-400 hover:bg-slate-800 hover:text-slate-200'
                  }`}
                >
                  <Icon className="w-5 h-5" />
                  <span className="flex-1 text-left">{item.label}</span>
                  {locked && <Lock className="w-3.5 h-3.5 text-slate-600 flex-shrink-0" />}
                </button>
              </li>
            );
          })}
        </ul>
      </nav>

      <div className="p-4 border-t border-slate-800">
        <div className="bg-slate-800 rounded-lg p-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-xs text-slate-400">System Status</span>
            <span className="flex items-center gap-1 text-xs text-green-400">
              <span className="w-2 h-2 bg-green-400 rounded-full"></span>
              Active
            </span>
          </div>
          <p className="text-xs text-slate-500">All systems operational</p>
        </div>
      </div>
    </div>
  );
}
