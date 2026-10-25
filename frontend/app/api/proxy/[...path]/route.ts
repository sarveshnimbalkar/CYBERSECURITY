import { NextRequest, NextResponse } from 'next/server';
import { apiKeyForRole, dashboardRole } from '@/lib/dashboard-auth';
import { backendApiUrl } from '@/lib/backend-url';
import { BodyTooLargeError, readLimitedBody } from '@/lib/limited-body';

type Context = { params: Promise<{ path: string[] }> };

async function forward(request: NextRequest, context: Context) {
  const apiUrl = backendApiUrl();
  const role = dashboardRole(request.headers.get('authorization'));
  if (!role) {
    return NextResponse.json({ detail: 'Authentication required' }, { status: 401 });
  }
  const apiKey = apiKeyForRole(role);
  if (!apiUrl || !apiKey) {
    return NextResponse.json({ detail: 'Backend connection is not configured' }, { status: 503 });
  }

  const { path } = await context.params;
  const endpoint = `/${path.join('/')}`;
  const readOnly = /^\/(health|sensors|analytics|threats|incidents(?:\/[a-f0-9-]+(?:\/(?:detections|response-actions))?)?|containers(?:\/[a-zA-Z0-9_-]+)?|demo\/scenarios|model\/status)$/;
  const incidentAction = /^\/incidents\/[a-f0-9-]+\/(acknowledge|resolve|false-positive)$/;
  const demoAction = /^\/demo\/(seed-baseline|simulate-all|simulate\/[a-z_]+)$/;
  const permitted = (request.method === 'GET' && readOnly.test(endpoint)) ||
    (request.method === 'POST' && (incidentAction.test(endpoint) || demoAction.test(endpoint) || endpoint === '/model/train'));
  if (!permitted) {
    return NextResponse.json({ detail: 'Route is not available through the dashboard' }, { status: 403 });
  }
  if (request.method !== 'GET') {
    const origin = request.headers.get('origin');
    const expected = process.env.DASHBOARD_PUBLIC_ORIGIN || request.nextUrl.origin;
    if (!origin || origin !== expected || request.headers.get('sec-fetch-site') === 'cross-site') {
      return NextResponse.json({ detail: 'Invalid request origin' }, { status: 403 });
    }
  }
  const target = new URL(`${apiUrl.replace(/\/$/, '')}/${path.map(encodeURIComponent).join('/')}`);
  target.search = request.nextUrl.search;
  try {
    const body = ['GET', 'HEAD'].includes(request.method) ? undefined : await readLimitedBody(request);
    const upstream = await fetch(target, {
      method: request.method,
      headers: {
        'X-API-Key': apiKey,
        'Content-Type': request.headers.get('content-type') || 'application/json',
      },
      body,
      cache: 'no-store',
    });
    return new NextResponse(upstream.body, {
      status: upstream.status,
      headers: { 'Content-Type': upstream.headers.get('content-type') || 'application/json' },
    });
  } catch (error) {
    if (error instanceof BodyTooLargeError) return NextResponse.json({ detail: 'Request body too large' }, { status: 413 });
    return NextResponse.json({ detail: 'Backend unavailable' }, { status: 502 });
  }
}

export const GET = forward;
export const POST = forward;
export const PUT = forward;
export const PATCH = forward;
export const DELETE = forward;
