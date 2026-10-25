export function backendApiUrl(): string | null {
  if (process.env.BACKEND_API_URL) return process.env.BACKEND_API_URL.replace(/\/$/, '');
  if (process.env.BACKEND_HOSTPORT) return `http://${process.env.BACKEND_HOSTPORT}/api`;
  return null;
}
