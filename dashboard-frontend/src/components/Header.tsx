import { Search, Bell, LogOut } from 'lucide-react';
import { SessionUser, ROLE_LABELS, ROLE_COLORS } from '@/lib/auth';

interface HeaderProps {
  searchQuery?: string;
  onSearchChange?: (q: string) => void;
  user?: SessionUser | null;
  onLogout?: () => void;
}

export function Header({ searchQuery = '', onSearchChange, user, onLogout }: HeaderProps) {
  const role = user?.role;
  const colors = role ? ROLE_COLORS[role] : null;

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
              className="w-full pl-10 pr-4 py-2 bg-slate-800 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>
        </div>

        <div className="flex items-center gap-4 ml-6">
          <button className="relative p-2 text-slate-400 hover:text-slate-200 transition-colors">
            <Bell className="w-5 h-5" />
            <span className="absolute top-1 right-1 w-2 h-2 bg-red-500 rounded-full"></span>
          </button>

          <div className="flex items-center gap-3">
            <div className="w-8 h-8 bg-gradient-to-br from-purple-500 to-pink-600 rounded-full flex items-center justify-center text-xs font-bold text-white">
              {user ? user.fullName.split(' ').map(n => n[0]).join('').slice(0, 2).toUpperCase() : 'U'}
            </div>
            <div className="text-sm">
              <div className="text-slate-200">{user?.fullName ?? 'Loading...'}</div>
              {role && colors ? (
                <span className={`text-xs font-medium ${colors.text}`}>
                  {ROLE_LABELS[role]}
                </span>
              ) : (
                <div className="text-xs text-slate-500">SOC Team</div>
              )}
            </div>
          </div>

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
