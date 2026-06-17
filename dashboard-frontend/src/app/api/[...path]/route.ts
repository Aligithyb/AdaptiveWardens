import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8003';

async function proxy(req: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const { path } = await params;
  const url = new URL(req.url);
  const target = `${BACKEND_URL}/api/${path.join('/')}${url.search}`;

  const headers = new Headers(req.headers);
  headers.delete('host');

  const body = req.method !== 'GET' && req.method !== 'HEAD' ? await req.arrayBuffer() : undefined;

  const upstream = await fetch(target, {
    method: req.method,
    headers,
    body,
    // @ts-ignore — Next.js fetch supports duplex
    duplex: 'half',
    signal: AbortSignal.timeout(30_000),
  });

  const resHeaders = new Headers(upstream.headers);
  resHeaders.delete('transfer-encoding');

  return new NextResponse(upstream.body, {
    status: upstream.status,
    headers: resHeaders,
  });
}

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
