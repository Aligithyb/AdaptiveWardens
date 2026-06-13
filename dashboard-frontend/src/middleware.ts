import { NextRequest, NextResponse } from 'next/server';

export function middleware(req: NextRequest) {
  const session = req.cookies.get('session')?.value;
  const { pathname } = req.nextUrl;

  if (pathname.startsWith('/dashboard')) {
    if (session !== 'authenticated') {
      return NextResponse.redirect(new URL('/login', req.url));
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: ['/dashboard/:path*'],
};
