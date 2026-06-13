import { NextRequest, NextResponse } from 'next/server';

const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'gradproject2025';

export async function POST(req: NextRequest) {
  try {
    const { password } = await req.json();
    if (password === DASHBOARD_PASSWORD) {
      const res = NextResponse.json({ ok: true });
      res.cookies.set('session', 'authenticated', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: 60 * 60 * 4, // 4 hours
        path: '/',
      });
      return res;
    }
    return NextResponse.json({ error: 'invalid password' }, { status: 401 });
  } catch {
    return NextResponse.json({ error: 'bad request' }, { status: 400 });
  }
}
