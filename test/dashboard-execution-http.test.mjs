import test from 'node:test';
import assert from 'node:assert/strict';
import fsPromises, { mkdtemp, mkdir, writeFile, rm, realpath, readdir, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { connect } from 'node:net';
import { syncBuiltinESMExports } from 'node:module';
import { startDashboard } from '../src/dashboard/server.mjs';

async function fixture(callback) {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), 'sec-hub-web-http-'));
  const runs = path.join(root, 'runs'), target = path.join(root, 'target');
  await mkdir(runs); await mkdir(target);
  const config = path.join(root, 'scanner.json'), manifest = path.join(root, 'execution.json');
  await writeFile(config, JSON.stringify({ tools: { osv: { command: process.execPath, args: [path.join(root, 'scanner.mjs')] } } }));
  await writeFile(path.join(root, 'scanner.mjs'), `import{writeFileSync}from'node:fs';if(process.argv.includes('--version'))console.log('fixture 1');else{const i=process.argv.indexOf('--output-file');writeFileSync(process.argv[i+1],JSON.stringify({results:[]}));}`);
  await writeFile(manifest, JSON.stringify({ schemaVersion: 1, targets: [{ label: 'HTTP fixture', path: target, config, tools: ['osv'], ai: false, timeoutMs: 5000 }] }));
  try { return await callback({ root, runs, manifest }); } finally { await rm(root, { recursive: true, force: true }); }
}
function request(dashboard, route, { method = 'GET', headers = {}, body, rawHeaders } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(route, dashboard.url);
    const req = http.request(url, { method, headers: rawHeaders ?? headers }, res => {
      let text = ''; res.setEncoding('utf8'); res.on('data', x => { text += x; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text, json: () => JSON.parse(text) }));
    });
    req.on('error', reject); req.end(body);
  });
}
function auth(dashboard, extra = {}) { return { Authorization: `Bearer ${new URL(dashboard.executionUrl).hash.slice(9)}`, ...extra }; }
async function discover(dashboard) {
  const response = await request(dashboard, '/api/execution', { headers: auth(dashboard) });
  assert.equal(response.status, 200); return response.json();
}
function mutation(dashboard, discovery, value = {}) {
  return { method: 'POST', headers: auth(dashboard, { Origin: new URL(dashboard.url).origin, 'X-Sec-Hub-CSRF': discovery.csrfToken, 'Content-Type': 'application/json' }), body: JSON.stringify(value) };
}

// A missing opt-in branch or leaked launch credentials breaks these observable boundaries.
test('execution is explicitly enabled and session credentials stay out of public responses', () => fixture(async ({ runs, manifest }) => {
  const readonly = await startDashboard({ runs });
  try { assert.equal(readonly.executionUrl, undefined); assert.equal((await request(readonly, '/api/execution')).status, 404); } finally { await readonly.close(); }
  const dashboard = await startDashboard({ runs, executionConfig: manifest });
  try {
    assert.match(dashboard.executionUrl, /\/#session=[a-f0-9]{64}$/);
    const discovery = await discover(dashboard);
    assert.equal(discovery.enabled, true); assert.equal(discovery.generation, 0); assert.equal(discovery.currentJob, null);
    assert.equal((await request(dashboard, '/api/catalog')).json().snapshot.refresh, 'explicit');
    assert.deepEqual(Object.keys(discovery.targets[0]).sort(), ['id', 'label', 'toolIds']);
    assert.deepEqual(discovery.targets[0].toolIds, ['osv']);
    const token = new URL(dashboard.executionUrl).hash.slice(9);
    for (const route of ['/', '/assets/app.mjs', '/assets/execution-view.mjs', '/api/catalog', '/api/execution/jobs/not-an-id']) {
      const response = await request(dashboard, route, { headers: auth(dashboard) });
      assert.ok(!response.text.includes(token)); assert.ok(!response.text.includes(discovery.csrfToken));
    }
    assert.equal((await request(dashboard, '/api/execution')).status, 401);
    const badBearer = await request(dashboard, '/api/execution', { headers: { Authorization: `Bearer ${'0'.repeat(64)}` } });
    assert.equal(badBearer.status, 401); assert.deepEqual(badBearer.json(), { error: { code: 'unauthorized' } });
    assert.equal(badBearer.headers['www-authenticate'], 'Bearer');
    assert.equal((await request(dashboard, '/api/execution?token=bad', { headers: auth(dashboard) })).status, 400);
  } finally { await dashboard.close(); }
}));

// Removing pre-body admission or strict schemas must never create a scan output directory.
test('HTTP rejects untrusted headers and bodies without admitting scan work', () => fixture(async ({ runs, manifest }) => {
  const dashboard = await startDashboard({ runs, executionConfig: manifest });
  try {
    const discovery = await discover(dashboard), valid = mutation(dashboard, discovery, { targetId: discovery.targets[0].id, toolIds: ['osv'] });
    const cases = [
      { ...valid, headers: { ...valid.headers, Host: `localhost:${new URL(dashboard.url).port}` } },
      { ...valid, headers: { ...valid.headers, Origin: 'null' } },
      { ...valid, headers: Object.fromEntries(Object.entries(valid.headers).filter(([key]) => key !== 'Origin')) },
      { ...valid, headers: { ...valid.headers, Authorization: 'Bearer ' + '0'.repeat(64) } },
      { ...valid, headers: { ...valid.headers, 'X-Sec-Hub-CSRF': '0'.repeat(64) } },
      { ...valid, headers: { ...valid.headers, 'Sec-Fetch-Site': 'cross-site' } },
      { ...valid, headers: { ...valid.headers, 'Content-Type': 'text/plain' } },
      { ...valid, headers: { ...valid.headers, 'Content-Encoding': 'gzip' } },
      { ...valid, body: '{' }, { ...valid, body: '[]' },
      mutation(dashboard, discovery, { targetId: discovery.targets[0].id, toolIds: ['osv'], path: '/tmp/injection' }),
      mutation(dashboard, discovery, { targetId: discovery.targets[0].id, toolIds: ['anthropic'] }),
      mutation(dashboard, discovery, { targetId: discovery.targets[0].id, toolIds: ['osv', 'osv'] }),
      { ...valid, body: JSON.stringify({ padding: 'x'.repeat(4096) }) },
    ];
    for (const options of cases) {
      const response = await request(dashboard, '/api/execution/jobs', options);
      assert.ok([400,401,403,413].includes(response.status), `unexpected rejection ${response.status}`);
      assert.deepEqual(Object.keys(response.json().error), ['code']);
    }
    const raw = Object.entries(valid.headers).flatMap(([key, value]) => [key, value]);
    for (const [key, value] of [['Authorization',valid.headers.Authorization],['Origin',valid.headers.Origin],['X-Sec-Hub-CSRF',discovery.csrfToken]]) {
      const response = await request(dashboard, '/api/execution/jobs', { ...valid, rawHeaders: ['Host', new URL(dashboard.url).host, ...raw, key, value] });
      assert.equal(response.status,403);
    }
    assert.deepEqual(await readdir(runs), []);
    assert.deepEqual((await discover(dashboard)).jobs, []);
  } finally { await dashboard.close(); }
}));

async function waitForJob(dashboard, id, expected) {
  const deadline = Date.now() + 8000;
  while (Date.now() < deadline) {
    const response = await request(dashboard, `/api/execution/jobs/${id}`, { headers: auth(dashboard) });
    assert.equal(response.status, 200);
    const job = response.json().job;
    if (expected(job)) return job;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('job did not reach expected state');
}

// Losing the refresh reservation or replacing only half the catalog would expose stale/mixed detail.
test('completed scans publish only on explicit atomic refresh and resolve to existing detail routes', () => fixture(async ({ runs, manifest }) => {
  const dashboard = await startDashboard({ runs, executionConfig: manifest });
  try {
    const discovery = await discover(dashboard);
    const started = await request(dashboard, '/api/execution/jobs', mutation(dashboard, discovery, { targetId: discovery.targets[0].id, toolIds: ['osv'] }));
    assert.equal(started.status, 202);
    const job = await waitForJob(dashboard, started.json().job.id, value => ['completed','failed','cancelled'].includes(value.state));
    assert.equal(job.state, 'completed'); assert.equal(job.reportsReady, true); assert.ok(job.resultRunId);
    assert.equal((await discover(dashboard)).currentJob, null);
    assert.deepEqual((await request(dashboard, '/api/catalog')).json().artifacts, []);
    const refreshed = await request(dashboard, '/api/execution/catalog/refresh', mutation(dashboard, discovery));
    assert.equal(refreshed.status, 200);
    const payload = refreshed.json(); assert.equal(payload.generation, 1); assert.equal(payload.catalog.snapshot.refresh, 'explicit');
    assert.deepEqual(payload.results, [{ jobId: job.id, runId: job.resultRunId, artifactId: payload.catalog.artifacts[0].id }]);
    const detail = await request(dashboard, `/api/artifacts/${payload.results[0].artifactId}`);
    assert.equal(detail.status, 200); assert.equal(detail.json().run.id, job.resultRunId);
    assert.deepEqual((await request(dashboard, '/api/catalog')).json(), payload.catalog);
    // Fill the bounded catalog ahead of the UUID output: a ready job can be absent.
    for (let index = 0; index < 128; index += 1) {
      const directory = path.join(runs, `!${String(index).padStart(3, '0')}`);
      await mkdir(directory); await writeFile(path.join(directory, 'run.json'), JSON.stringify(savedRun(`filler-${index}`)));
    }
    const truncated = await request(dashboard, '/api/execution/catalog/refresh', mutation(dashboard, discovery));
    assert.equal(truncated.status, 200); assert.equal(truncated.json().catalog.snapshot.truncated, true);
    assert.deepEqual(truncated.json().results, [{ jobId: job.id, runId: job.resultRunId, artifactId: null }]);
    const malformed = await request(dashboard, '/api/execution/jobs/not-an-id', { headers: auth(dashboard) });
    assert.equal(malformed.status, 400); assert.deepEqual(malformed.json(), { error: { code: 'invalid_request' } });
    const cancelTerminal = await request(dashboard, `/api/execution/jobs/${job.id}/cancel`, mutation(dashboard, discovery));
    assert.equal(cancelTerminal.status, 200); assert.equal(cancelTerminal.json().job.state, 'completed');
  } finally { await dashboard.close(); }
}));

// Dropping controller.close or releasing admission early would leave this real scanner alive.
test('concurrent starts reserve one slot and cancellation/shutdown wait for real scanner cleanup', () => fixture(async ({ root, runs, manifest }) => {
  const pidFile = path.join(root, 'scanner.pid');
  await writeFile(path.join(root, 'scanner.mjs'), `import{writeFileSync}from'node:fs';if(process.argv.includes('--version'))console.log('fixture 1');else{process.on('SIGTERM',()=>{});writeFileSync(${JSON.stringify(pidFile)},String(process.pid));setInterval(()=>{},1000);}`);
  const dashboard = await startDashboard({ runs, executionConfig: manifest });
  let scannerPid;
  try {
    const discovery = await discover(dashboard), start = mutation(dashboard, discovery, { targetId: discovery.targets[0].id, toolIds: ['osv'] });
    const responses = await Promise.all([request(dashboard, '/api/execution/jobs', start), request(dashboard, '/api/execution/jobs', start)]);
    assert.deepEqual(responses.map(response => response.status).sort(), [202,409]);
    const jobId = responses.find(response => response.status === 202).json().job.id;
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && !scannerPid) {
      try { scannerPid = Number(await readFile(pidFile, 'utf8')); } catch {}
      if (!scannerPid) await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.ok(scannerPid, 'actual scanner must be running before cancellation');
    const cancel = await request(dashboard, `/api/execution/jobs/${jobId}/cancel`, mutation(dashboard, discovery));
    assert.equal(cancel.status, 202); assert.equal(cancel.json().job.state, 'cancelling');
    const repeated = await request(dashboard, `/api/execution/jobs/${jobId}/cancel`, mutation(dashboard, discovery));
    assert.equal(repeated.status, 202); assert.equal(repeated.json().job.state, 'cancelling');
    assert.equal((await request(dashboard, '/api/execution/jobs', start)).status, 409);
    let closed = false; dashboard.closed.then(() => { closed = true; });
    const closure = dashboard.close();
    await new Promise(resolve => setTimeout(resolve, 30));
    assert.equal(closed, false, 'HTTP listener shutdown must not settle before owned scanner cleanup');
    await closure; await dashboard.closed;
    assert.throws(() => process.kill(scannerPid, 0), { code: 'ESRCH' });
    await dashboard.close();
  } finally {
    await dashboard.close();
    if (scannerPid) try { process.kill(scannerPid, 'SIGKILL'); } catch {}
  }
}));

function rawRequest(dashboard, headers, payload = '') {
  const url = new URL(dashboard.url);
  return new Promise((resolve, reject) => {
    const socket = connect({ host: url.hostname, port: Number(url.port) });
    let text = '';
    const deadline = setTimeout(() => { socket.destroy(); reject(new Error('raw HTTP deadline')); }, 7000);
    socket.setEncoding('utf8');
    socket.on('connect', () => socket.write(`POST /api/execution/jobs HTTP/1.1\r\nHost: ${url.host}\r\n${headers.join('\r\n')}\r\n\r\n${payload}`));
    socket.on('data', chunk => { text += chunk; });
    socket.on('error', reject);
    socket.on('close', () => { clearTimeout(deadline); resolve(text); });
  });
}

// These raw requests catch reading before auth, trusting only declared length, or retaining stalled bodies.
test('execution bodies enforce independent declared/chunk limits and a five-second read deadline', () => fixture(async ({ runs, manifest }) => {
  const dashboard = await startDashboard({ runs, executionConfig: manifest });
  try {
    const discovery = await discover(dashboard);
    const headers = Object.entries(mutation(dashboard, discovery).headers).map(([key,value]) => `${key}: ${value}`);
    const unauthorized = await rawRequest(dashboard, ['Content-Type: application/json','Content-Length: 50']);
    assert.match(unauthorized, /^HTTP\/1\.1 401 /);
    const declared = await rawRequest(dashboard, [...headers,'Content-Length: 4097']);
    assert.match(declared, /^HTTP\/1\.1 413 /);
    const chunked = await rawRequest(dashboard, [...headers,'Transfer-Encoding: chunked'], `1001\r\n${'x'.repeat(4097)}\r\n0\r\n\r\n`);
    assert.match(chunked, /^HTTP\/1\.1 413 /);
    const startedAt = Date.now();
    const stalled = await rawRequest(dashboard, [...headers,'Content-Length: 50'], '{');
    assert.match(stalled, /^HTTP\/1\.1 408 /);
    assert.ok(Date.now() - startedAt >= 4900 && Date.now() - startedAt < 6500);
    assert.deepEqual(await readdir(runs), []); assert.deepEqual((await discover(dashboard)).jobs, []);
  } finally { await dashboard.close(); }
}));

const savedRun = id => ({ schemaVersion: 1, id, startedAt: '2026-10-28T00:00:00Z', endedAt: '2026-10-28T00:01:00Z', target: { path: '/fixture' }, status: 'completed', tools: [], findings: [] });
// A partial refresh swap, early admission release, or unjoined refresh breaks this boundary.
test('refresh retains failed snapshots, swaps records atomically, and is joined by close', () => fixture(async ({ runs, manifest }) => {
  await writeFile(path.join(runs, 'run.json'), JSON.stringify(savedRun('old-run')));
  const dashboard = await startDashboard({ runs, executionConfig: manifest });
  const originalOpendir = fsPromises.opendir;
  let release;
  try {
    const discovery = await discover(dashboard), before = (await request(dashboard, '/api/catalog')).json(), id = before.artifacts[0].id;
    fsPromises.opendir = async (filename, ...args) => { if (filename === runs) throw new Error('private path and argv must never escape'); return originalOpendir(filename, ...args); };
    const failed = await request(dashboard, '/api/execution/catalog/refresh', mutation(dashboard, discovery));
    assert.equal(failed.status, 500); assert.deepEqual(failed.json(), { error: { code: 'refresh_failed' } });
    assert.deepEqual((await request(dashboard, '/api/catalog')).json(), before); assert.equal((await discover(dashboard)).generation, 0);
    fsPromises.opendir = originalOpendir;
    await writeFile(path.join(runs, 'run.json'), JSON.stringify(savedRun('new-run')));
    let entered;
    const loading = new Promise(resolve => { entered = resolve; });
    const gate = new Promise(resolve => { release = resolve; });
    fsPromises.opendir = async (filename, ...args) => { if (filename === runs) { entered(); await gate; } return originalOpendir(filename, ...args); };
    const refresh = request(dashboard, '/api/execution/catalog/refresh', mutation(dashboard, discovery));
    await loading;
    assert.equal((await request(dashboard, `/api/artifacts/${id}`)).json().run.id, 'old-run');
    assert.deepEqual((await request(dashboard, '/api/catalog')).json(), before);
    const busy = await request(dashboard, '/api/execution/jobs', mutation(dashboard, discovery, { targetId: discovery.targets[0].id, toolIds: ['osv'] }));
    assert.equal(busy.status, 409);
    release();
    const replaced = await refresh; assert.equal(replaced.status, 200); assert.equal(replaced.json().generation, 1);
    assert.equal((await request(dashboard, `/api/artifacts/${id}`)).json().run.id, 'new-run');
    fsPromises.opendir = originalOpendir;
    let closingEntered;
    const closingLoad = new Promise(resolve => { closingEntered = resolve; });
    const closingGate = new Promise(resolve => { release = resolve; });
    fsPromises.opendir = async (filename, ...args) => { if (filename === runs) { closingEntered(); await closingGate; } return originalOpendir(filename, ...args); };
    const disconnectedRefresh = request(dashboard, '/api/execution/catalog/refresh', mutation(dashboard, discovery)).catch(error => error);
    await closingLoad;
    let settled = false;
    const closure = dashboard.close().then(() => { settled = true; });
    await new Promise(resolve => setTimeout(resolve, 30)); assert.equal(settled, false);
    release(); await closure; await dashboard.closed; await disconnectedRefresh;
  } finally { release?.(); fsPromises.opendir = originalOpendir; await dashboard.close(); }
}));

// Reusing a startup token would allow stale tabs to execute against a replacement server.
test('restarting execution rotates session and rejects old-server credentials', () => fixture(async ({ runs, manifest }) => {
  const first = await startDashboard({ runs, executionConfig: manifest });
  const oldHeaders = auth(first);
  const oldDiscovery = await discover(first);
  await first.close();
  const second = await startDashboard({ runs, executionConfig: manifest });
  try {
    assert.notEqual(auth(second).Authorization, oldHeaders.Authorization);
    const rejected = await request(second, '/api/execution', { headers: oldHeaders });
    assert.equal(rejected.status, 401); assert.deepEqual(rejected.json(), { error: { code: 'unauthorized' } });
    const current = await discover(second);
    assert.notEqual(current.csrfToken, oldDiscovery.csrfToken);
  } finally { await second.close(); }
}));

// Rejecting closed immediately on listener error would leave owned scanner descendants alive.
test('runtime listener errors reject execution close only after active scanner cleanup', () => fixture(async ({ root, runs, manifest }) => {
  const originalCreateServer = http.createServer;
  let server, scannerPid;
  const pidFile = path.join(root, 'error-scanner.pid');
  await writeFile(path.join(root, 'scanner.mjs'), `import{writeFileSync}from'node:fs';if(process.argv.includes('--version'))console.log('fixture 1');else{process.on('SIGTERM',()=>{});writeFileSync(${JSON.stringify(pidFile)},String(process.pid));setInterval(()=>{},1000);}`);
  http.createServer = (...args) => { server = originalCreateServer(...args); return server; };
  syncBuiltinESMExports();
  let dashboard;
  try {
    dashboard = await startDashboard({ runs, executionConfig: manifest });
    const discovery = await discover(dashboard);
    const started = await request(dashboard, '/api/execution/jobs', mutation(dashboard, discovery, { targetId: discovery.targets[0].id, toolIds: ['osv'] }));
    assert.equal(started.status, 202);
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && !scannerPid) {
      try { scannerPid = Number(await readFile(pidFile, 'utf8')); } catch {}
      if (!scannerPid) await new Promise(resolve => setTimeout(resolve, 20));
    }
    assert.ok(scannerPid, 'actual scanner must be running before listener failure');
    let settled = false;
    const outcome = dashboard.closed.then(() => { settled = true; return null; }, error => { settled = true; return error; });
    server.emit('error', new Error('private listener diagnostics'));
    await new Promise(resolve => setTimeout(resolve, 30)); assert.equal(settled, false);
    const error = await outcome; assert.equal(error.message, 'Dashboard server failed');
    assert.throws(() => process.kill(scannerPid, 0), { code: 'ESRCH' });
    await assert.rejects(dashboard.close(), { message: 'Dashboard server failed' });
  } finally {
    http.createServer = originalCreateServer; syncBuiltinESMExports();
    await dashboard?.close().catch(() => {});
    if (scannerPid) try { process.kill(scannerPid, 'SIGKILL'); } catch {}
  }
}));

// Enabled startup must also stop before binding when a signal arrives during trusted asset loading.
test('execution startup abort during asset preload never attaches a listener', () => fixture(async ({ runs, manifest }) => {
  const originalLstat = fsPromises.lstat, originalListen = http.Server.prototype.listen;
  let release, entered, listenerCalls = 0;
  const loading = new Promise(resolve => { entered = resolve; });
  const gate = new Promise(resolve => { release = resolve; });
  fsPromises.lstat = async (filename, ...args) => {
    if (String(filename).includes(`${path.sep}src${path.sep}web${path.sep}`)) { entered(); await gate; }
    return originalLstat(filename, ...args);
  };
  http.Server.prototype.listen = function (...args) { listenerCalls += 1; return originalListen.apply(this, args); };
  syncBuiltinESMExports();
  const controller = new AbortController();
  const startup = startDashboard({ runs, executionConfig: manifest, signal: controller.signal });
  try {
    await loading; controller.abort(); release();
    await assert.rejects(startup, /aborted/); assert.equal(listenerCalls, 0);
  } finally { release(); fsPromises.lstat = originalLstat; http.Server.prototype.listen = originalListen; syncBuiltinESMExports(); }
}));
