import { timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import { lstat, readFile, realpath } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareRuns } from '../compare.mjs';
import { redactValue } from '../redaction.mjs';
import { loadCatalog } from './catalog.mjs';
import { RequestPolicyError, validateRequest } from './http-policy.mjs';
import { createExecutionSession, ExecutionPolicyError, readExecutionJson, validateExecutionRequest } from './execution-policy.mjs';

const RESPONSE_LIMIT = 64 * 1024 * 1024;
const SECURITY_HEADERS = Object.freeze({
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'none'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
});
const MIME = Object.freeze({ '/': 'text/html; charset=utf-8', '/assets/app.mjs': 'text/javascript; charset=utf-8', '/assets/style.css': 'text/css; charset=utf-8', '/assets/view-model.mjs': 'text/javascript; charset=utf-8', '/assets/i18n.mjs': 'text/javascript; charset=utf-8', '/assets/execution-view.mjs': 'text/javascript; charset=utf-8' });
const RUN_STATUSES = new Set(['completed', 'partial', 'failed']);
const TOOL_STATUSES = new Set(['completed', 'failed', 'skipped', 'timed_out', 'cancelled', 'imported']);
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info', 'unknown']);
const VERIFICATIONS = new Set(['candidate', 'reported', 'confirmed']);
const COMPARISON_CATEGORIES = new Set(['new', 'regressed', 'existing', 'resolved', 'unobserved']);
const IDENTITY_METHODS = new Set(['native', 'dependency', 'location', 'weak']);
const ERROR_MESSAGES = Object.freeze({
  bad_request: '요청 형식이 올바르지 않습니다.',
  forbidden: '허용되지 않은 요청입니다.',
  not_found: '요청한 항목을 찾을 수 없습니다.',
  method_not_allowed: '허용되지 않은 HTTP 메서드입니다.',
  artifact_unavailable: '비교에 사용할 수 있는 실행 아티팩트가 아닙니다.',
  comparison_invalid: '저장된 두 실행을 비교할 수 없습니다.',
  response_too_large: '응답이 대시보드 용량 제한을 초과했습니다.',
  internal_error: '요청을 처리하지 못했습니다.',
});

function jsonBuffer(value) {
  let body;
  try { body = Buffer.from(JSON.stringify(value), 'utf8'); } catch { throw new Error('serialize'); }
  if (body.length > RESPONSE_LIMIT) throw new ResponseError('response_too_large', 413);
  return body;
}
class ResponseError extends Error {
  constructor(code, status) { super(code); this.code = code; this.status = status; }
}
function errorBody(code) { return { error: { code, message: ERROR_MESSAGES[code] ?? ERROR_MESSAGES.internal_error } }; }
function makeResponse(status, contentType, body = Buffer.alloc(0), extra = {}) {
  return { status, contentType, body, extra };
}
function jsonResponse(value, status = 200) { return makeResponse(status, 'application/json; charset=utf-8', jsonBuffer(value)); }

async function preloadAssets() {
  const src = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const files = new Map([
    ['/', path.join(src, 'web', 'index.html')],
    ['/assets/app.mjs', path.join(src, 'web', 'app.mjs')],
    ['/assets/style.css', path.join(src, 'web', 'style.css')],
    ['/assets/view-model.mjs', path.join(src, 'web', 'view-model.mjs')],
    ['/assets/i18n.mjs', path.join(src, 'web', 'i18n.mjs')],
    ['/assets/execution-view.mjs', path.join(src, 'web', 'execution-view.mjs')],
  ]);
  const assets = new Map();
  for (const [route, filename] of files) {
    const info = await lstat(filename);
    if (info.isSymbolicLink() || !info.isFile()) throw new TypeError('trusted dashboard asset unavailable');
    assets.set(route, await readFile(filename));
  }
  return assets;
}

// Fields handled structurally are excluded from the generic traversal. Explicit
// field names remain stable even when an inherited secret matches a schema key.
function redactFields(record, fields, redact) {
  const names = new Set(fields);
  const safe = redact(Object.fromEntries(Object.entries(record).filter(([key]) => !names.has(key))));
  for (const field of fields) if (record[field] !== undefined) safe[field] = redact(record[field]);
  return safe;
}
function redactTarget(target, redact) {
  return redactFields(target, ['path', 'revision', 'dirty'], redact);
}
function redactFinding(finding, redact) {
  const { sourceRecords, location, severity, verification, ...rest } = finding;
  const safe = redactFields(rest, ['id', 'toolId', 'ruleId', 'title', 'description', 'aliases', 'references', 'evidence', 'rawRef', 'sources'], redact);
  if (severity !== undefined) safe.severity = SEVERITIES.has(severity) ? severity : redact(severity);
  if (verification !== undefined) safe.verification = VERIFICATIONS.has(verification) ? verification : redact(verification);
  if (location !== undefined) safe.location = location && typeof location === 'object' && !Array.isArray(location)
    ? redactFields(location, ['path', 'package', 'version', 'url', 'line'], redact) : redact(location);
  if (sourceRecords !== undefined) safe.sourceRecords = Array.isArray(sourceRecords) ? sourceRecords.map((item) => redactFinding(item, redact)) : redact(sourceRecords);
  return safe;
}
function redactRun(run, redact) {
  const { schemaVersion, status, target, tools, findings, ...rest } = run;
  const safe = redactFields(rest, ['id', 'startedAt', 'endedAt', 'provenance', 'verification', 'verificationPassed', 'pendingIntegrations'], redact);
  safe.schemaVersion = schemaVersion;
  safe.status = RUN_STATUSES.has(status) ? status : redact(status);
  if (target !== undefined) safe.target = target ? redactTarget(target, redact) : redact(target);
  if (tools !== undefined) safe.tools = Array.isArray(tools) ? tools.map((tool) => {
    const { status: toolStatus, selected, findings: toolFindings, ...metadata } = tool;
    const item = redactFields(metadata, ['id', 'source', 'version', 'name', 'reason', 'execution', 'provenance'], redact);
    item.status = TOOL_STATUSES.has(toolStatus) ? toolStatus : redact(toolStatus);
    if (selected !== undefined) item.selected = selected;
    if (toolFindings !== undefined) item.findings = Array.isArray(toolFindings) ? toolFindings.map((finding) => redactFinding(finding, redact)) : redact(toolFindings);
    return item;
  }) : redact(tools);
  if (findings !== undefined) safe.findings = Array.isArray(findings) ? findings.map((finding) => redactFinding(finding, redact)) : redact(findings);
  return safe;
}
function redactComparison(comparison, redact, generated = false) {
  const side = (item) => {
    const { target, status, ...metadata } = item;
    return { ...redactFields(metadata, ['id', 'provenance'], redact), target: { path: redact(target.path), ...(target.revision !== undefined ? { revision: redact(target.revision) } : {}), ...(target.dirty !== undefined ? { dirty: redact(target.dirty) } : {}) }, status: RUN_STATUSES.has(status) ? status : redact(status) };
  };
  const coverageSide = (item) => {
    if (item === null) return null;
    const { status, selected, ...metadata } = item;
    return { ...redact(metadata), status: TOOL_STATUSES.has(status) ? status : redact(status), ...(selected !== undefined ? { selected } : {}) };
  };
  return {
    schemaVersion: comparison.schemaVersion,
    kind: comparison.kind,
    identityVersion: comparison.identityVersion,
    baseline: side(comparison.baseline),
    current: side(comparison.current),
    status: comparison.status,
    coverage: comparison.coverage.map((record) => ({ toolId: redact(record.toolId), baseline: coverageSide(record.baseline), current: coverageSide(record.current), reasons: record.reasons.map(redact) })),
    entries: comparison.entries.map((entry) => ({ id: generated ? entry.id : redact(entry.id), identity: generated ? entry.identity : redact(entry.identity), identityMethod: IDENTITY_METHODS.has(entry.identityMethod) ? entry.identityMethod : redact(entry.identityMethod), category: COMPARISON_CATEGORIES.has(entry.category) ? entry.category : redact(entry.category), ...(entry.before ? { before: redactFinding(entry.before, redact) } : {}), ...(entry.after ? { after: redactFinding(entry.after, redact) } : {}), reasons: entry.reasons.map(redact) })),
    counts: { ...comparison.counts },
    notices: comparison.notices.map(redact),
    gate: { failOn: comparison.gate.failOn, violations: comparison.gate.violations.map(generated ? (id) => id : redact), unknown: comparison.gate.unknown.map(generated ? (id) => id : redact), exitCode: comparison.gate.exitCode },
  };
}
function redactSummary(summary, kind, redact) {
  if (!summary) return summary;
  if (kind === 'run') {
    return { runId: redact(summary.runId), status: RUN_STATUSES.has(summary.status) ? summary.status : redact(summary.status), target: { path: redact(summary.target.path), ...(summary.target.revision !== undefined ? { revision: redact(summary.target.revision) } : {}), ...(typeof summary.target.dirty === 'boolean' ? { dirty: summary.target.dirty } : {}) }, startedAt: redact(summary.startedAt), endedAt: redact(summary.endedAt), findingCount: summary.findingCount, tools: summary.tools.map((tool) => ({ id: redact(tool.id), status: TOOL_STATUSES.has(tool.status) ? tool.status : redact(tool.status), ...(tool.selected !== undefined ? { selected: tool.selected } : {}) })) };
  }
  return { baselineId: redact(summary.baselineId), currentId: redact(summary.currentId), target: { path: redact(summary.target.path) }, status: summary.status, counts: { ...summary.counts }, gate: { failOn: summary.gate.failOn, exitCode: summary.gate.exitCode } };
}
function redactedEntry(entry, redact) {
  return { id: entry.id, kind: entry.kind, state: entry.state, label: redact(entry.label), ...(entry.sha256 !== undefined ? { sha256: entry.sha256 } : {}), ...(entry.summary !== undefined ? { summary: redactSummary(entry.summary, entry.kind, redact) } : {}), ...(entry.error !== undefined ? { error: { code: entry.error.code, message: entry.error.message } } : {}) };
}
function catalogResponse(catalog, redact) {
  return { schemaVersion: catalog.schemaVersion, kind: catalog.kind, snapshot: { createdAt: redact(catalog.snapshot.createdAt), refresh: catalog.snapshot.refresh, truncated: catalog.snapshot.truncated, limits: { ...catalog.snapshot.limits }, notices: catalog.snapshot.notices.map((notice) => ({ code: notice.code, message: notice.message })) }, artifacts: catalog.artifacts.map((entry) => redactedEntry(entry, redact)) };
}
function queryValue(searchParams, name, required = true) {
  const values = searchParams.getAll(name);
  if (values.length > 1 || (required && values.length !== 1) || (!required && values.length > 1)) throw new ResponseError('bad_request', 400);
  return values[0];
}

function routeRequest(request, policy, registry, catalog, assets, redact) {
  const { pathname, searchParams } = policy;
  const method = request.method;
  const known = pathname === '/' || Object.hasOwn(MIME, pathname) || pathname === '/api/catalog' || pathname === '/api/compare' || /^\/api\/artifacts\/[a-f0-9]{64}$/.test(pathname);
  if (!known) throw new ResponseError('not_found', 404);
  if (pathname === '/api/compare') {
    if (method !== 'GET') throw Object.assign(new ResponseError('method_not_allowed', 405), { allow: 'GET' });
  } else if (!['GET', 'HEAD'].includes(method)) {
    throw Object.assign(new ResponseError('method_not_allowed', 405), { allow: 'GET, HEAD' });
  }
  if (Object.hasOwn(MIME, pathname)) return makeResponse(200, MIME[pathname], assets.get(pathname));
  if (pathname === '/api/catalog') return jsonResponse(catalogResponse(catalog, redact));
  const artifactMatch = pathname.match(/^\/api\/artifacts\/([a-f0-9]{64})$/);
  if (artifactMatch) {
    const entry = catalog.artifacts.find((item) => item.id === artifactMatch[1]);
    if (!entry) throw new ResponseError('not_found', 404);
    const record = registry.get(entry.id);
    const detail = { schemaVersion: 1, artifact: redactedEntry(entry, redact), ...(record?.kind === 'run' ? { run: redactRun(record.payload, redact) } : {}), ...(record?.kind === 'comparison' ? { comparison: redactComparison(record.payload, redact) } : {}) };
    return jsonResponse(detail);
  }
  if (pathname === '/api/compare') {
    const allowed = new Set(['baseline', 'current', 'failOn']);
    for (const key of searchParams.keys()) if (!allowed.has(key)) throw new ResponseError('bad_request', 400);
    const baselineId = queryValue(searchParams, 'baseline');
    const currentId = queryValue(searchParams, 'current');
    const failOn = queryValue(searchParams, 'failOn', false) ?? 'high';
    if (!/^[a-f0-9]{64}$/.test(baselineId) || !/^[a-f0-9]{64}$/.test(currentId) || !['critical', 'high', 'medium', 'low', 'info', 'any', 'none'].includes(failOn)) throw new ResponseError('bad_request', 400);
    const baselineEntry = catalog.artifacts.find((entry) => entry.id === baselineId);
    const currentEntry = catalog.artifacts.find((entry) => entry.id === currentId);
    if (!baselineEntry || !currentEntry) throw new ResponseError('not_found', 404);
    if (baselineEntry.kind !== 'run' || currentEntry.kind !== 'run' || baselineEntry.state !== 'ready' || currentEntry.state !== 'ready') throw new ResponseError('artifact_unavailable', 422);
    const baseline = registry.get(baselineId), current = registry.get(currentId);
    let comparison;
    try { comparison = compareRuns(baseline.payload, current.payload, { failOn }); } catch { throw new ResponseError('comparison_invalid', 422); }
    const safeComparison = redactComparison(comparison, redact, true);
    return jsonResponse({ schemaVersion: 1, inputs: { baseline: { id: baseline.id, sha256: baseline.sha256 }, current: { id: current.id, sha256: current.sha256 } }, comparison: safeComparison });
  }
  throw new ResponseError('not_found', 404);
}

function send(response, request, result) {
  const body = result.body;
  const headers = { ...SECURITY_HEADERS, ...result.extra, ...(result.contentType ? { 'Content-Type': result.contentType } : {}), 'Content-Length': String(body.length), 'Connection': 'close' };
  response.writeHead(result.status, headers);
  if (request.method === 'HEAD') response.end();
  else response.end(body);
}

function explicitRefreshSnapshot(snapshot) {
  return { ...snapshot, catalog: { ...snapshot.catalog, snapshot: { ...snapshot.catalog.snapshot, refresh: 'explicit' } } };
}
function executionPath(request) {
  return typeof request.url === 'string' && /^\/api\/execution(?:\/|\?|$)/.test(request.url);
}
function exactFields(body, fields) {
  if (Object.keys(body).length !== fields.length || fields.some((field) => !Object.hasOwn(body, field))) throw new ExecutionPolicyError('invalid_request', 400);
}

function mapResults(snapshot, jobs) {
  return jobs.filter((job) => job.reportsReady && job.resultRunId).map((job) => {
    const artifact = snapshot.catalog.artifacts.find((entry) => entry.kind === 'run' && entry.state === 'ready' && snapshot.records.get(entry.id)?.payload?.id === job.resultRunId);
    return { jobId: job.id, runId: job.resultRunId, artifactId: artifact?.id ?? null };
  });
}
function hasDesktopSession(request, token) {
  const header = request.headers['x-sec-hub-desktop'];
  return typeof header === 'string' && /^[a-f0-9]{64}$/.test(header) && timingSafeEqual(Buffer.from(header, 'hex'), token);
}

/** Start a loopback-only viewer. Only a trusted manifest enables HTTP execution. */
export async function startDashboard({ runs, port = 0, signal, executionConfig, desktopCatalog } = {}) {
  if (typeof runs !== 'string' || !path.isAbsolute(runs)) throw new TypeError('runs must be an absolute directory');
  if (!Number.isInteger(port) || port < 0 || port > 65535) throw new TypeError('port must be an integer from 0 through 65535');
  if (signal !== undefined && (typeof signal !== 'object' || typeof signal.addEventListener !== 'function')) throw new TypeError('signal must be an AbortSignal');
  if (signal?.aborted) throw new TypeError('dashboard startup aborted');
  if (desktopCatalog && (executionConfig !== undefined || !path.isAbsolute(desktopCatalog.runs ?? '') || !/^[a-f0-9]{64}$/.test(desktopCatalog.token ?? ''))) throw new TypeError('invalid desktop catalog');
  const desktopToken = desktopCatalog && Buffer.from(desktopCatalog.token, 'hex');
  let desktopSnapshot;
  let jobs;
  let ExecutionError;
  let session;
  if (executionConfig !== undefined) {
    if (typeof executionConfig !== 'string' || !path.isAbsolute(executionConfig)) throw new TypeError('executionConfig must be an absolute manifest filename');
    const [{ loadExecutionConfig }, controllerModule] = await Promise.all([import('./execution-config.mjs'), import('./jobs.mjs')]);
    ExecutionError = controllerModule.ExecutionError;
    const configuration = await loadExecutionConfig({ filename: executionConfig, runsRoot: runs });
    jobs = controllerModule.createJobController({ configuration });
    session = createExecutionSession();
  }
  let snapshot;
  let assets;
  try {
    snapshot = await loadCatalog(runs);
    if (jobs) snapshot = explicitRefreshSnapshot(snapshot);
    assets = await preloadAssets();
    if (signal?.aborted) throw new TypeError('dashboard startup aborted');
  } catch (error) { await jobs?.close(); throw error; }
  let generation = 0;
  let closing = false;
  const redactionEnv = { ...process.env };
  const redact = (value) => redactValue(value, redactionEnv);
  const sockets = new Set();
  async function routeExecution(request, policy) {
    const address = server.address();
    const actualPort = typeof address === 'object' && address ? address.port : port;
    validateExecutionRequest(request, actualPort, session);
    if (closing) throw new ExecutionPolicyError('execution_closing', 503);
    const { pathname } = policy;
    if (pathname === '/api/execution' && request.method === 'GET') return jsonResponse({ enabled: true, csrfToken: session.csrfToken, ...jobs.describe(), generation });
    const getMatch = pathname.match(/^\/api\/execution\/jobs\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/);
    const cancelMatch = pathname.match(/^\/api\/execution\/jobs\/([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\/cancel$/);
    if (pathname.startsWith('/api/execution/jobs/') && !getMatch && !cancelMatch) throw new ExecutionPolicyError('invalid_request', 400);
    if (getMatch && request.method === 'GET') return jsonResponse({ job: jobs.get(getMatch[1]) });
    if (request.method !== 'POST') throw new ExecutionPolicyError('method_not_allowed', 405);
    if (pathname !== '/api/execution/jobs' && pathname !== '/api/execution/catalog/refresh' && !cancelMatch) throw new ExecutionPolicyError('not_found', 404);
    const body = await readExecutionJson(request);
    if (closing) throw new ExecutionPolicyError('execution_closing', 503);
    if (pathname === '/api/execution/jobs') {
      exactFields(body, ['targetId', 'toolIds']);
      return jsonResponse({ job: jobs.start(body) }, 202);
    }
    exactFields(body, []);
    if (cancelMatch) {
      const job = jobs.cancel(cancelMatch[1]);
      return jsonResponse({ job }, ['running', 'cancelling'].includes(job.state) ? 202 : 200);
    }
    return jobs.withRefresh(async () => {
      let replacement;
      try { replacement = explicitRefreshSnapshot(await loadCatalog(runs)); } catch { throw new ExecutionPolicyError('refresh_failed', 500); }
      const nextGeneration = generation + 1;
      const catalog = catalogResponse(replacement.catalog, redact);
      const results = mapResults(replacement, jobs.describe().jobs);
      // Serialize first: an oversized/unserializable response must retain the prior snapshot.
      const result = jsonResponse({ catalog, generation: nextGeneration, results });
      snapshot = replacement;
      generation = nextGeneration;
      return result;
    });
  }
  const server = createServer(async (request, response) => {
    let result;
    const isExecution = Boolean(jobs) && executionPath(request);
    try {
      const address = server.address();
      const actualPort = typeof address === 'object' && address ? address.port : port;
      const policy = validateRequest(request, actualPort);
      const visible = desktopSnapshot && hasDesktopSession(request, desktopToken) ? desktopSnapshot : snapshot;
      result = isExecution ? await routeExecution(request, policy) : routeRequest(request, policy, visible.records, visible.catalog, assets, redact);
    } catch (error) {
      if (isExecution) {
        const known = error instanceof ExecutionPolicyError || (ExecutionError && error instanceof ExecutionError);
        const legacyPolicy = error instanceof RequestPolicyError;
        const code = known ? error.code : legacyPolicy ? error.code : 'internal_error';
        const status = known ? error.statusCode : legacyPolicy ? error.status : 500;
        result = jsonResponse({ error: { code } }, status);
        if (status === 401) result.extra = { 'WWW-Authenticate': 'Bearer' };
        request.pause();
      } else {
        const code = error instanceof RequestPolicyError ? error.code : error instanceof ResponseError ? error.code : 'internal_error';
        const status = error instanceof RequestPolicyError ? error.status : error instanceof ResponseError ? error.status : 500;
        const allow = error.allow ? { Allow: error.allow } : {};
        try { result = makeResponse(status, 'application/json; charset=utf-8', jsonBuffer(errorBody(code)), allow); }
        catch { result = makeResponse(500, 'application/json; charset=utf-8', Buffer.from(JSON.stringify(errorBody('internal_error')))); }
      }
    }
    if (!response.destroyed) {
      send(response, request, result);
      // Rejected bodies are never drained. Close once the constant response is flushed.
      if (isExecution && result.status >= 400) response.once('finish', () => request.socket.destroy());
    }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxConnections = 64;
  server.on('connection', (socket) => { sockets.add(socket); socket.once('close', () => sockets.delete(socket)); });

  let closedResolve;
  let closedReject;
  let started = false;
  let runtimeFailure;
  const closed = new Promise((resolve, reject) => { closedResolve = resolve; closedReject = reject; });
  void closed.catch(() => {});
  let closePromise;
  const close = () => {
    if (closePromise) return closePromise;
    closing = true;
    // Calling close synchronously invalidates admission and requests abort before HTTP teardown.
    const jobClosure = jobs ? jobs.close() : Promise.resolve();
    const httpClosure = new Promise((resolve, reject) => {
      if (!server.listening) { resolve(); return; }
      server.close((error) => error ? reject(error) : resolve());
      server.closeIdleConnections?.();
      for (const socket of sockets) socket.destroy();
    });
    closePromise = (async () => {
      const outcomes = await Promise.allSettled([jobClosure, httpClosure]);
      const rejected = outcomes.find((outcome) => outcome.status === 'rejected');
      if (rejected) throw rejected.reason;
      if (runtimeFailure) throw runtimeFailure;
    })();
    void closePromise.then(closedResolve, closedReject);
    void closePromise.catch(() => {});
    return closePromise;
  };
  server.on('error', () => {
    if (!started) return;
    runtimeFailure = new Error('Dashboard server failed');
    void close().catch(() => {});
  });
  let abortHandler;
  try {
    await new Promise((resolve, reject) => {
      const onError = (error) => { server.off('listening', onListening); reject(error); };
      const onListening = () => { server.off('error', onError); resolve(); };
      server.once('error', onError);
      server.once('listening', onListening);
      server.listen({ host: '127.0.0.1', port, exclusive: true });
    });
    started = true;
    if (signal) {
      abortHandler = () => { void close().catch(() => {}); };
      signal.addEventListener('abort', abortHandler, { once: true });
      if (signal.aborted) {
        signal.removeEventListener('abort', abortHandler);
        await close();
        throw new TypeError('dashboard startup aborted');
      }
    }
  } catch (error) { await close().catch(() => {}); throw error; }
  const actualPort = server.address().port;
  const url = `http://127.0.0.1:${actualPort}/`;
  return {
    url,
    ...(desktopCatalog ? { async refreshDesktopCatalog(jobs, generation = 1, isCurrent = () => true) {
      if (closing) throw new Error('dashboard is closing');
      const replacement = explicitRefreshSnapshot(await loadCatalog(desktopCatalog.runs));
      const value = { catalog: catalogResponse(replacement.catalog, redact), generation, results: mapResults(replacement, jobs) };
      jsonBuffer(value);
      if (closing || !isCurrent()) throw new Error('dashboard changed');
      desktopSnapshot = replacement;
      return value;
    } } : {}),
    ...(session ? { executionUrl: `${url}#session=${session.token}` } : {}),
    close: async () => {
      if (abortHandler) signal.removeEventListener('abort', abortHandler);
      // Preserve the legacy readonly public-close behavior after listener failure.
      if (!jobs && runtimeFailure) { await close().catch(() => {}); return; }
      await close();
    },
    closed,
  };
}
