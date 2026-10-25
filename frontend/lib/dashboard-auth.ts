import { timingSafeEqual } from 'node:crypto';

export type DashboardRole = 'viewer' | 'analyst' | 'admin';

function equal(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function dashboardRole(authorization: string | null): DashboardRole | null {
  if (!authorization?.startsWith('Basic ')) return null;
  let supplied = '';
  try {
    supplied = Buffer.from(authorization.slice(6), 'base64').toString('utf8');
  } catch {
    return null;
  }
  const separator = supplied.indexOf(':');
  if (separator < 0) return null;
  const username = supplied.slice(0, separator);
  const password = supplied.slice(separator + 1);
  const accounts: Array<{ role: DashboardRole; user?: string; password?: string }> = [
    { role: 'admin', user: process.env.DASHBOARD_ADMIN_USERNAME || process.env.DASHBOARD_USERNAME, password: process.env.DASHBOARD_ADMIN_PASSWORD || process.env.DASHBOARD_PASSWORD },
    { role: 'analyst', user: process.env.DASHBOARD_ANALYST_USERNAME, password: process.env.DASHBOARD_ANALYST_PASSWORD },
    { role: 'viewer', user: process.env.DASHBOARD_VIEWER_USERNAME, password: process.env.DASHBOARD_VIEWER_PASSWORD },
  ];
  for (const account of accounts) {
    if (account.user && account.password && equal(username, account.user) && equal(password, account.password)) {
      return account.role;
    }
  }
  return null;
}

export function apiKeyForRole(role: DashboardRole): string | undefined {
  if (role === 'admin') return process.env.CLOUDGUARD_ADMIN_API_KEY || process.env.CLOUDGUARD_API_KEY;
  if (role === 'analyst') return process.env.CLOUDGUARD_ANALYST_API_KEY;
  return process.env.CLOUDGUARD_VIEWER_API_KEY;
}
