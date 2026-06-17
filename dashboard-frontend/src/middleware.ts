import { NextRequest, NextResponse } from 'next/server';
import { verifySessionToken } from '@/lib/auth';

export async function middleware(req: NextRequest) {
  const { pathname } = req.nextUrl;

  if (pathname === '/' || pathname.startsWith('/dashboard')) {
    const token = req.cookies.get('session')?.value;
    if (!token) {
      return NextResponse.redirect(new URL('/login', req.url));
    }

    const user = await verifySessionToken(token);
    if (!user) {
      const res = NextResponse.redirect(new URL('/login', req.url));
      res.cookies.set('session', '', { maxAge: 0, path: '/' });
      return res;
    }

    const res = NextResponse.next();
    res.headers.set('x-user-role', user.role);
    res.headers.set('x-user-name', user.username);
    res.headers.set('x-user-fullname', user.fullName);
    return res;
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/', '/dashboard/:path*'],
};
