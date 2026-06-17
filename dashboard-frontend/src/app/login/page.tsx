"use client"

import { Shield, Eye, EyeOff, AlertTriangle, Lock } from 'lucide-react';
import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function LoginPage() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const router = useRouter();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) return;

    setLoading(true);
    setError('');

    try {
      const res = await fetch('/api/auth', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username.trim(), password }),
      });

      if (res.ok) {
        router.push('/dashboard');
      } else {
        const data = await res.json().catch(() => ({}));
        if (res.status === 503) {
          setError('Authentication service unavailable. Please try again.');
        } else {
          setError(data.error || 'Invalid credentials. Please try again.');
        }
      }
    } catch {
      setError('Network error. Please check your connection.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col">
      {/* Top security bar */}
      <div className="bg-red-950/60 border-b border-red-900/40 px-6 py-1.5 flex items-center justify-center gap-2">
        <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
        <p className="text-xs text-red-300 font-medium tracking-wide">
          RESTRICTED SYSTEM — AUTHORIZED PERSONNEL ONLY — ALL ACCESS IS MONITORED AND LOGGED
        </p>
      </div>

      <div className="flex-1 flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-md">

          {/* Logo + Title */}
          <div className="text-center mb-10">
            <div className="relative inline-block mb-5">
              <div className="w-20 h-20 bg-gradient-to-br from-cyan-500 to-blue-700 rounded-2xl flex items-center justify-center shadow-lg shadow-cyan-500/20">
                <Shield className="w-10 h-10 text-white" />
              </div>
              <span className="absolute -bottom-1 -right-1 w-5 h-5 bg-green-500 rounded-full border-2 border-slate-950 flex items-center justify-center">
                <span className="w-1.5 h-1.5 bg-white rounded-full" />
              </span>
            </div>
            <h1 className="text-3xl font-bold text-slate-100 tracking-tight">AdaptiveWardens</h1>
            <p className="text-slate-500 mt-1 text-sm">Security Operations Center</p>
            <div className="mt-3 inline-flex items-center gap-1.5 px-3 py-1 bg-slate-800 border border-slate-700 rounded-full">
              <Lock className="w-3 h-3 text-cyan-400" />
              <span className="text-xs text-slate-400">Secure Access Portal</span>
            </div>
          </div>

          {/* Card */}
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl shadow-2xl shadow-black/40 backdrop-blur-sm">
            <div className="px-8 pt-7 pb-2 border-b border-slate-800">
              <h2 className="text-slate-200 font-semibold">Sign In to Dashboard</h2>
              <p className="text-xs text-slate-500 mt-0.5">Use your SOC credentials to continue</p>
            </div>

            <form onSubmit={handleSubmit} className="px-8 py-6 space-y-5">
              {/* Username */}
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-2 uppercase tracking-wider">
                  Username
                </label>
                <input
                  type="text"
                  value={username}
                  onChange={e => { setUsername(e.target.value); setError(''); }}
                  placeholder="Enter your username"
                  autoFocus
                  autoComplete="username"
                  className="w-full px-4 py-3 bg-slate-800 border border-slate-700 rounded-xl text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all text-sm"
                />
              </div>

              {/* Password */}
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-2 uppercase tracking-wider">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={e => { setPassword(e.target.value); setError(''); }}
                    placeholder="Enter your password"
                    autoComplete="current-password"
                    className="w-full px-4 py-3 pr-12 bg-slate-800 border border-slate-700 rounded-xl text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500/30 transition-all text-sm"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(v => !v)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-slate-300 transition-colors"
                  >
                    {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Error */}
              {error && (
                <div className="flex items-start gap-2 px-3 py-2.5 bg-red-950/50 border border-red-800/50 rounded-lg">
                  <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                  <p className="text-sm text-red-300">{error}</p>
                </div>
              )}

              {/* Submit */}
              <button
                type="submit"
                disabled={loading || !username.trim() || !password}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-600 hover:to-blue-700 disabled:opacity-40 disabled:cursor-not-allowed rounded-xl text-white font-semibold text-sm transition-all shadow-lg shadow-cyan-500/20 hover:shadow-cyan-500/30"
              >
                {loading ? (
                  <>
                    <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Authenticating…
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    Sign In Securely
                  </>
                )}
              </button>
            </form>

          </div>

          {/* Footer */}
          <p className="text-center text-xs text-slate-700 mt-6">
            AdaptiveWardens SOC Platform · Access is monitored · Unauthorized use is prohibited
          </p>
        </div>
      </div>
    </div>
  );
}
