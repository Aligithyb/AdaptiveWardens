export type UserRole = 'admin' | 'soc_analyst' | 'it_staff' | 'read_only';

export interface SessionUser {
  username: string;
  role: UserRole;
  fullName: string;
  exp: number;
}

export const ROLE_LABELS: Record<UserRole, string> = {
  admin: 'Administrator',
  soc_analyst: 'SOC Analyst',
  it_staff: 'IT Staff',
  read_only: 'Read Only',
};

export const ROLE_COLORS: Record<UserRole, { text: string; bg: string; border: string }> = {
  admin:      { text: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30'    },
  soc_analyst:{ text: 'text-cyan-400',   bg: 'bg-cyan-500/10',   border: 'border-cyan-500/30'   },
  it_staff:   { text: 'text-green-400',  bg: 'bg-green-500/10',  border: 'border-green-500/30'  },
  read_only:  { text: 'text-slate-400',  bg: 'bg-slate-500/10',  border: 'border-slate-500/30'  },
};

export const ROLE_PERMISSIONS: Record<UserRole, string[]> = {
  admin:       ['dashboard', 'live-sessions', 'attack-map', 'ioc-summary', 'mitre-attack', 'metrics', 'reports', 'threat-intelligence', 'effectiveness'],
  soc_analyst: ['dashboard', 'live-sessions', 'ioc-summary', 'mitre-attack', 'attack-map', 'reports', 'effectiveness'],
  it_staff:    ['dashboard', 'live-sessions', 'metrics', 'effectiveness'],
  read_only:   ['dashboard', 'attack-map'],
};

export function canAccess(role: UserRole, view: string): boolean {
  return ROLE_PERMISSIONS[role]?.includes(view) ?? false;
}

const SESSION_DURATION_MS = 4 * 60 * 60 * 1000; // 4 hours

function b64urlEncode(input: string): string {
  return btoa(input).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64urlDecode(input: string): string {
  // Restore padding
  const padded = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = padded.length % 4;
  return atob(pad ? padded + '='.repeat(4 - pad) : padded);
}

function getSecret(): string {
  return process.env.SESSION_SECRET || 'adaptive-wardens-fallback-secret-change-in-production';
}

async function importKey(): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(getSecret()),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

export async function createSessionToken(user: Omit<SessionUser, 'exp'>): Promise<string> {
  const payload: SessionUser = { ...user, exp: Date.now() + SESSION_DURATION_MS };
  const payloadB64 = b64urlEncode(JSON.stringify(payload));

  const key = await importKey();
  const sigBuf = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payloadB64));
  const sigArr = new Uint8Array(sigBuf);
  let sigStr = '';
  for (let i = 0; i < sigArr.length; i++) sigStr += String.fromCharCode(sigArr[i]);
  const sigB64 = b64urlEncode(sigStr);

  return `${payloadB64}.${sigB64}`;
}

export async function verifySessionToken(token: string): Promise<SessionUser | null> {
  try {
    const dot = token.lastIndexOf('.');
    if (dot < 1) return null;
    const payloadB64 = token.slice(0, dot);
    const sigB64 = token.slice(dot + 1);

    const key = await importKey();
    const sigStr = b64urlDecode(sigB64);
    const sigBytes = Uint8Array.from(sigStr, c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify(
      'HMAC', key, sigBytes, new TextEncoder().encode(payloadB64)
    );
    if (!valid) return null;

    const user = JSON.parse(b64urlDecode(payloadB64)) as SessionUser;
    if (user.exp < Date.now()) return null;

    return user;
  } catch {
    return null;
  }
}
