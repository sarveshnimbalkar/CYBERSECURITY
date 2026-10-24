import { NextRequest, NextResponse } from 'next/server';

type Context = { params: Promise<{ path: string[] }> };

async function forward(request: NextRequest, context: Context) {
  const apiUrl = process.env.BACKEND_API_URL;
  const apiKey = process.env.CLOUDGUARD_API_KEY;
  if (!apiUrl || !apiKey) {
    return NextResponse.json({ detail: 'Backend connection is not configured' }, { status: 503 });
  }

  const { path } = await context.params;
  const endpoint = `/${path.join('/')}`;
  const readOnly = /^\/(health|analytics|threats|incidents(?:\/[a-f0-9-]+(?:\/(?:detections|response-actions))?)?|containers(?:\/[a-zA-Z0-9_-]+)?|demo\/scenarios|model\/status)$/;
  const incidentAction = /^\/incidents\/[a-f0-9-]+\/(acknowledge|resolve|false-positive)$/;
  const demoAction = /^\/demo\/(seed-baseline|simulate-all|simulate\/[a-z_]+)$/;
  const permitted = (request.method === 'GET' && readOnly.test(endpoint)) ||
    (request.method === 'POST' && (incidentAction.test(endpoint) || demoAction.test(endpoint) || endpoint === '/model/train'));
  if (!permitted) {
    return NextResponse.json({ detail: 'Route is not available through the dashboard' }, { status: 403 });
  }
  const target = new URL(`${apiUrl.replace(/\/$/, '')}/${path.map(encodeURIComponent).join('/')}`);
  target.search = request.nextUrl.search;
  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers: {
        'X-API-Key': apiKey,
        'Content-Type': request.headers.get('content-type') || 'application/json',
      },
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : await request.arrayBuffer(),
      cache: 'no-store',
    });
    return new NextResponse(upstream.body, {
      status: upstream.status,
      headers: { 'Content-Type': upstream.headers.get('content-type') || 'application/json' },
    });
  } catch {
    return NextResponse.json({ detail: 'Backend unavailable' }, { status: 502 });
  }
}

export const GET = forward;
export const POST = forward;
export const PUT = forward;
export const PATCH = forward;
export const DELETE = forward;
