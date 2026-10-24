import { timingSafeEqual } from 'node:crypto';
import { NextRequest, NextResponse } from 'next/server';

function equal(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function proxy(request: NextRequest) {
  const username = process.env.DASHBOARD_USERNAME;
  const password = process.env.DASHBOARD_PASSWORD;
  if (!username || !password) {
    return new NextResponse('Dashboard credentials are not configured', { status: 503 });
  }

  const header = request.headers.get('authorization') || '';
  let supplied = '';
  if (header.startsWith('Basic ')) {
    try {
      supplied = Buffer.from(header.slice(6), 'base64').toString('utf8');
    } catch {
      supplied = '';
    }
  }
  const separator = supplied.indexOf(':');
  const suppliedUser = separator >= 0 ? supplied.slice(0, separator) : '';
  const suppliedPassword = separator >= 0 ? supplied.slice(separator + 1) : '';
  if (!equal(suppliedUser, username) || !equal(suppliedPassword, password)) {
    return new NextResponse('Authentication required', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="CloudGuard"' },
    });
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
