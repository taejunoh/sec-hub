import test from 'node:test';
import assert from 'node:assert/strict';
import { createConnection } from 'node:net';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { validateRequest } from '../src/dashboard/http-policy.mjs';
import { startDashboard } from '../src/dashboard/server.mjs';
import { compareRuns } from '../src/compare.mjs';

const run = (id, findings = [], overrides = {}) => ({ schemaVersion: 1, id, startedAt: '2026-10-27T00:00:00Z', endedAt: '2026-10-27T00:01:00Z', target: { path: '/synthetic/target' }, status: 'completed', tools: [{ id: 'osv', status: 'completed', selected: true, findings }], findings, ...overrides });
const finding = (severity = 'high') => ({ toolId: 'osv', ruleId: 'SYNTHETIC', title: 'synthetic finding', severity, location: { path: 'package-lock.json', package: 'npm:demo', version: '1.0.0' }, verification: 'candidate' });
async function sandbox(fn) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sec-hub-server-'));
  try { return await fn(root); } finally { await rm(root, { recursive: true, force: true }); }
}
function rawRequest(port, lines) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port });
    const chunks = [];
    socket.on('connect', () => socket.write(`${lines.join('\r\n')}\r\n\r\n`));
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    socket.setTimeout(2000, () => socket.destroy(new Error('request timed out')));
  });
}

test('accepts only exact loopback authorities, matching origins and same-origin fetch metadata', () => {
  const valid = { headers: { host: '127.0.0.1:4321' }, url: '/api/catalog', method: 'GET' };
  assert.deepEqual(validateRequest(valid, 4321), { pathname: '/api/catalog', searchParams: new URLSearchParams() });
  assert.deepEqual(validateRequest({ ...valid, headers: { host: 'localhost:4321', origin: 'http://localhost:4321' } }, 4321).pathname, '/api/catalog');
  for (const request of [
    { ...valid, headers: {} },
    { ...valid, headers: { host: ['127.0.0.1:4321', '127.0.0.1:4321'] } },
    { ...valid, headers: { host: '127.0.0.1:4322' } },
    { ...valid, headers: { host: '127.0.0.1:4321', origin: 'null' } },
    { ...valid, headers: { host: '127.0.0.1:4321', origin: ['http://127.0.0.1:4321', 'http://127.0.0.1:4321'] } },
    { ...valid, headers: { host: '127.0.0.1:4321', origin: 'https://127.0.0.1:4321' } },
    { ...valid, headers: { host: '127.0.0.1:4321', 'sec-fetch-site': 'cross-site' } },
  ]) assert.throws(() => validateRequest(request, 4321));
});

test('rejects raw paths before URL normalization and allows only compare query strings', () => {
  const headers = { host: '127.0.0.1:4321' };
  for (const url of ['/a/../api/catalog', '/%2e%2e/api/catalog', '/api%2fcatalog', '/api\\catalog', '//127.0.0.1/api/catalog', 'http://127.0.0.1:4321/api/catalog', '/api/catalog#x', '/api//catalog', '/api/./catalog']) {
    assert.throws(() => validateRequest({ headers, url, method: 'GET' }, 4321), undefined, url);
  }
  assert.throws(() => validateRequest({ headers, url: '/?x=1', method: 'GET' }, 4321));
  assert.throws(() => validateRequest({ headers, url: '/api/catalog?x=1', method: 'GET' }, 4321));
  assert.equal(validateRequest({ headers, url: '/api/compare?baseline=abc&current=def', method: 'GET' }, 4321).pathname, '/api/compare');
});

test('serves a bounded in-memory snapshot and pure comparisons with safe headers and no artifact mutation', async () => sandbox(async (root) => {
  const baseline = run('duplicate-id', [finding()]);
  const current = run('duplicate-id', [finding('critical')], { status: 'partial' });
  const baselineBytes = Buffer.from(JSON.stringify(baseline));
  const currentBytes = Buffer.from(JSON.stringify(current));
  await writeFile(path.join(root, 'run.json'), baselineBytes);
  const child = path.join(root, 'current');
  await mkdir(child);
  await writeFile(path.join(child, 'run.json'), currentBytes);
  await writeFile(path.join(root, 'report.html'), '<script>not trusted</script>');
  const dashboard = await startDashboard({ runs: root, port: 0 });
  try {
    const port = Number(new URL(dashboard.url).port);
    const catalogResponse = await rawRequest(port, ['GET /api/catalog HTTP/1.1', `Host: 127.0.0.1:${port}`, 'Connection: close']);
    assert.match(catalogResponse, /^HTTP\/1\.1 200/);
    assert.match(catalogResponse, /Cache-Control: no-store/i);
    assert.match(catalogResponse, /Content-Security-Policy:/i);
    const body = JSON.parse(catalogResponse.slice(catalogResponse.indexOf('\r\n\r\n') + 4));
    const runs = body.artifacts.filter((entry) => entry.kind === 'run');
    const compareResponse = await rawRequest(port, [`GET /api/compare?baseline=${runs[0].id}&current=${runs[1].id}&failOn=high HTTP/1.1`, `Host: 127.0.0.1:${port}`, 'Connection: close']);
    assert.match(compareResponse, /^HTTP\/1\.1 200/);
    const result = JSON.parse(compareResponse.slice(compareResponse.indexOf('\r\n\r\n') + 4));
    assert.deepEqual(result.comparison, compareRuns(baseline, current, { failOn: 'high' }));
    assert.equal(result.comparison.gate.exitCode, 2);
    const blocked = await rawRequest(port, ['GET /api/catalog HTTP/1.1', `Host: localhost:${port}`, 'Origin: http://evil.example', 'Connection: close']);
    assert.match(blocked, /^HTTP\/1\.1 403/);
    const head = await rawRequest(port, ['HEAD /api/catalog HTTP/1.1', `Host: 127.0.0.1:${port}`, 'Connection: close']);
    assert.match(head, /^HTTP\/1\.1 200/);
    assert.equal(head.split('\r\n\r\n')[1], '');
    const report = await rawRequest(port, ['GET /report.html HTTP/1.1', `Host: 127.0.0.1:${port}`, 'Connection: close']);
    assert.match(report, /^HTTP\/1\.1 404/);
    assert.deepEqual(await readFile(path.join(root, 'run.json')), baselineBytes);
    assert.deepEqual(await readFile(path.join(child, 'run.json')), currentBytes);
  } finally {
    await dashboard.close();
    await dashboard.closed;
  }
}));

test('redacts saved content while preserving schema, run/tool status and severity enums', async () => sandbox(async (root) => {
  const payload = run('redaction-test', [{ ...finding(), title: 'completed' }]);
  await writeFile(path.join(root, 'run.json'), Buffer.from(JSON.stringify(payload)));
  const old = process.env.TEST_API_KEY;
  process.env.TEST_API_KEY = 'completed';
  try {
    const dashboard = await startDashboard({ runs: root });
    try {
      const port = Number(new URL(dashboard.url).port);
      const catalogResponse = await rawRequest(port, ['GET /api/catalog HTTP/1.1', `Host: 127.0.0.1:${port}`, 'Connection: close']);
      const catalog = JSON.parse(catalogResponse.slice(catalogResponse.indexOf('\r\n\r\n') + 4));
      assert.equal(catalog.artifacts[0].summary.status, 'completed');
      assert.equal(catalog.artifacts[0].summary.tools[0].status, 'completed');
      const id = catalog.artifacts[0].id;
      const detailResponse = await rawRequest(port, [`GET /api/artifacts/${id} HTTP/1.1`, `Host: 127.0.0.1:${port}`, 'Connection: close']);
      const detail = JSON.parse(detailResponse.slice(detailResponse.indexOf('\r\n\r\n') + 4));
      assert.equal(detail.run.status, 'completed');
      assert.equal(detail.run.tools[0].status, 'completed');
      assert.equal(detail.run.findings[0].severity, 'high');
      assert.equal(detail.run.findings[0].title, '[REDACTED]');
    } finally { await dashboard.close(); }
  } finally {
    if (old === undefined) delete process.env.TEST_API_KEY;
    else process.env.TEST_API_KEY = old;
  }
}));

test('rejects startup when the supplied abort signal is already cancelled', async () => sandbox(async (root) => {
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(startDashboard({ runs: root, signal: controller.signal }), /aborted/i);
}));

test('redaction cannot rename fixed catalog or comparison envelope keys', async () => sandbox(async (root) => {
  const baseline = run('base');
  const current = run('current', [finding()]);
  await writeFile(path.join(root, 'run.json'), Buffer.from(JSON.stringify(baseline)));
  const child = path.join(root, 'current');
  await mkdir(child);
  await writeFile(path.join(child, 'run.json'), Buffer.from(JSON.stringify(current)));
  const old = process.env.TEST_API_KEY;
  try {
    process.env.TEST_API_KEY = 'snapshot';
    const snapshotServer = await startDashboard({ runs: root });
    let snapshotCatalog;
    try {
      const port = Number(new URL(snapshotServer.url).port);
      const response = await rawRequest(port, ['GET /api/catalog HTTP/1.1', `Host: 127.0.0.1:${port}`, 'Connection: close']);
      snapshotCatalog = JSON.parse(response.slice(response.indexOf('\r\n\r\n') + 4));
      assert.equal(snapshotCatalog.snapshot.refresh, 'restart');
    } finally { await snapshotServer.close(); }

    process.env.TEST_API_KEY = 'baseline';
    const comparisonServer = await startDashboard({ runs: root });
    try {
      const port = Number(new URL(comparisonServer.url).port);
      const catalogResponse = await rawRequest(port, ['GET /api/catalog HTTP/1.1', `Host: 127.0.0.1:${port}`, 'Connection: close']);
      const catalog = JSON.parse(catalogResponse.slice(catalogResponse.indexOf('\r\n\r\n') + 4));
      const runs = catalog.artifacts.filter((entry) => entry.kind === 'run');
      const response = await rawRequest(port, [`GET /api/compare?baseline=${runs[0].id}&current=${runs[1].id} HTTP/1.1`, `Host: 127.0.0.1:${port}`, 'Connection: close']);
      const body = JSON.parse(response.slice(response.indexOf('\r\n\r\n') + 4));
      assert.ok(body.comparison.baseline);
      assert.equal(body.comparison.baseline.status, 'completed');
    } finally { await comparisonServer.close(); }
  } finally {
    if (old === undefined) delete process.env.TEST_API_KEY;
    else process.env.TEST_API_KEY = old;
  }
}));

test('serves engine-valid source-record wrappers without assuming optional nested shapes', async () => sandbox(async (root) => {
  const leaf = finding();
  const wrapper = { toolId: 'osv', sourceRecords: [leaf], location: null, aliases: 'native-wrapper' };
  await writeFile(path.join(root, 'run.json'), Buffer.from(JSON.stringify(run('wrapped', [wrapper]))));
  const dashboard = await startDashboard({ runs: root });
  try {
    const port = Number(new URL(dashboard.url).port);
    const catalogResponse = await rawRequest(port, ['GET /api/catalog HTTP/1.1', `Host: 127.0.0.1:${port}`, 'Connection: close']);
    const catalog = JSON.parse(catalogResponse.slice(catalogResponse.indexOf('\r\n\r\n') + 4));
    assert.equal(catalog.artifacts[0].state, 'ready');
    const response = await rawRequest(port, [`GET /api/artifacts/${catalog.artifacts[0].id} HTTP/1.1`, `Host: 127.0.0.1:${port}`, 'Connection: close']);
    assert.match(response, /^HTTP\/1\.1 200/);
  } finally { await dashboard.close(); }
}));
