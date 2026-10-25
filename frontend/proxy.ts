import { NextRequest, NextResponse } from 'next/server';
import { dashboardRole } from './lib/dashboard-auth';

export function proxy(request: NextRequest) {
  if (!(process.env.DASHBOARD_ADMIN_USERNAME || process.env.DASHBOARD_USERNAME) || !(process.env.DASHBOARD_ADMIN_PASSWORD || process.env.DASHBOARD_PASSWORD)) {
    return new NextResponse('Dashboard credentials are not configured', { status: 503 });
  }
  if (!dashboardRole(request.headers.get('authorization'))) {
    return new NextResponse('Authentication required', {
      status: 401,
      headers: { 'WWW-Authenticate': 'Basic realm="CloudGuard"' },
    });
  }
  return NextResponse.next();
}

export const config = {
  matcher: ['/((?!_next/static|_next/image|favicon.ico|healthz|api/ingest/).*)'],
};
