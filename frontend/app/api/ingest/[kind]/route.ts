import { NextRequest, NextResponse } from 'next/server';
import { backendApiUrl } from '@/lib/backend-url';
import { BodyTooLargeError, readLimitedBody } from '@/lib/limited-body';

type Context = { params: Promise<{ kind: string }> };

export async function POST(request: NextRequest, context: Context) {
  const { kind } = await context.params;
  const targetPath = kind === 'falco' ? '/falco/events' : kind === 'heartbeat' ? '/sensors/heartbeat' : null;
  if (!targetPath) return NextResponse.json({ detail: 'Unknown ingestion route' }, { status: 404 });

  const apiUrl = backendApiUrl();
  if (!apiUrl) return NextResponse.json({ detail: 'Backend connection is not configured' }, { status: 503 });
  const apiKey = request.headers.get('x-api-key');
  if (!apiKey) return NextResponse.json({ detail: 'Sensor key required' }, { status: 401 });

  try {
    const body = await readLimitedBody(request);
    const upstream = await fetch(`${apiUrl}${targetPath}`, {
      method: 'POST',
      headers: { 'X-API-Key': apiKey, 'Content-Type': 'application/json' },
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
