const METHODS_WITH_PATH = new Set(['GET', 'HEAD']);
const CONTROL = /[\x00-\x1f\x7f]/;

export class RequestPolicyError extends Error {
  constructor(code, status) {
    super(code);
    this.name = 'RequestPolicyError';
    this.code = code;
    this.status = status;
  }
}

function headerValues(request, name) {
  const raw = request.rawHeaders;
  if (Array.isArray(raw)) {
    const values = [];
    for (let index = 0; index < raw.length; index += 2) if (String(raw[index]).toLowerCase() === name) values.push(String(raw[index + 1]));
    return values;
  }
  const value = request.headers?.[name];
  if (Array.isArray(value)) return value.map(String);
  return value === undefined ? [] : [String(value)];
}

function forbidden() { throw new RequestPolicyError('forbidden', 403); }
function badRequest() { throw new RequestPolicyError('bad_request', 400); }

/** Validate raw authority, origin and request-target syntax before URL parsing or routing. */
export function validateRequest(request, actualPort) {
  const hosts = headerValues(request, 'host');
  if (hosts.length !== 1) forbidden();
  const authority = hosts[0];
  const expectedPort = String(actualPort);
  if (authority !== `127.0.0.1:${expectedPort}` && authority !== `localhost:${expectedPort}`) forbidden();
  const origins = headerValues(request, 'origin');
  if (origins.length > 1) forbidden();
  if (origins.length === 1 && origins[0] !== `http://${authority}`) forbidden();
  const sites = headerValues(request, 'sec-fetch-site');
  if (sites.some((value) => value.trim().toLowerCase() === 'cross-site')) forbidden();
  if (sites.length > 1) forbidden();

  const target = request.url;
  if (typeof target !== 'string' || !target.startsWith('/') || target.startsWith('//') || CONTROL.test(target) || target.includes('\\') || target.includes('#')) badRequest();
  const queryIndex = target.indexOf('?');
  const pathname = queryIndex === -1 ? target : target.slice(0, queryIndex);
  const query = queryIndex === -1 ? '' : target.slice(queryIndex + 1);
  if (!pathname.startsWith('/') || pathname.includes('%') || pathname.includes('//')) badRequest();
  if (pathname.split('/').some((segment) => segment === '.' || segment === '..')) badRequest();
  if (pathname !== '/api/compare' && queryIndex !== -1) badRequest();
  if (query.includes('#') || CONTROL.test(query)) badRequest();
  if (!METHODS_WITH_PATH.has(request.method) && !(pathname === '/api/compare' && request.method === 'GET')) {
    // Method handling belongs to the router; syntax is still valid.
  }
  return { pathname, searchParams: new URLSearchParams(query) };
}
