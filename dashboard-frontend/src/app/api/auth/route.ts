import { NextRequest, NextResponse } from 'next/server';
import { createSessionToken, UserRole } from '@/lib/auth';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8003';

export async function POST(req: NextRequest) {
  try {
    const { username, password } = await req.json();
    if (!username || !password) {
      return NextResponse.json({ error: 'Username and password required' }, { status: 400 });
    }

    // Validate credentials against backend
    let userData: { username: string; full_name: string; role: UserRole };
    try {
      const backendRes = await fetch(`${BACKEND_URL}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
        signal: AbortSignal.timeout(8000),
      });

      if (!backendRes.ok) {
        return NextResponse.json({ error: 'Invalid credentials' }, { status: 401 });
      }
      userData = await backendRes.json();
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'TimeoutError') {
        return NextResponse.json({ error: 'Authentication service unavailable' }, { status: 503 });
      }
      return NextResponse.json({ error: 'Authentication service unavailable' }, { status: 503 });
    }

    const token = await createSessionToken({
      username: userData.username,
      role: userData.role,
      fullName: userData.full_name,
    });

    const res = NextResponse.json({ ok: true, role: userData.role, fullName: userData.full_name });
    // secure:true requires HTTPS — set false when no TLS (plain HTTP deployment)
    const useSecure = process.env.COOKIE_SECURE === 'true';
    res.cookies.set('session', token, {
      httpOnly: true,
      secure: useSecure,
      sameSite: 'lax',
      maxAge: 60 * 60 * 4, // 4 hours
      path: '/',
    });
    return res;
  } catch {
    return NextResponse.json({ error: 'Bad request' }, { status: 400 });
  }
}
