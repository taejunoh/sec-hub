import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createConnection } from 'node:net';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { compareRuns } from '../src/compare.mjs';
import { startDashboard } from '../src/dashboard/server.mjs';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workRoot = path.resolve(repo, '..', '..', 'work');
const run = (id, findings = []) => ({
  schemaVersion: 1,
  id,
  startedAt: '2026-10-27T00:00:00.000Z',
  endedAt: '2026-10-27T00:01:00.000Z',
  target: { path: '/synthetic/target' },
  status: 'completed',
  tools: [{ id: 'osv', selected: true, status: 'completed', findings }],
  findings,
});
const finding = (severity = 'high') => ({
  toolId: 'osv',
  ruleId: 'SYNTHETIC-ADVISORY',
  title: 'Synthetic advisory',
  severity,
  location: { path: 'package-lock.json', package: 'npm:synthetic', version: '1.0.0' },
  verification: 'candidate',
});

async function withFixture(fn) {
  const root = await mkdtemp(path.join(tmpdir(), 'sec-hub-dashboard-security-'));
  try {
    const baseline = run('saved-base');
    const current = run('saved-current', [finding()]);
    await writeFile(path.join(root, 'run.json'), JSON.stringify(baseline));
    const currentDir = path.join(root, 'current');
    await mkdir(currentDir);
    await writeFile(path.join(currentDir, 'run.json'), JSON.stringify(current));
    await writeFile(path.join(root, 'comparison.json'), JSON.stringify(compareRuns(baseline, current)));
    return await fn({ root, baseline, current });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

function rawRequest(port, requestLines) {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: '127.0.0.1', port });
    const chunks = [];
    socket.on('connect', () => socket.write(`${requestLines.join('\r\n')}\r\n\r\n`));
    socket.on('data', (chunk) => chunks.push(chunk));
    socket.on('error', reject);
    socket.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8');
      const boundary = raw.indexOf('\r\n\r\n');
      const [statusLine, ...headerLines] = raw.slice(0, boundary).split('\r\n');
      const headers = Object.fromEntries(headerLines.map((line) => {
        const separator = line.indexOf(':');
        return [line.slice(0, separator).trim().toLowerCase(), line.slice(separator + 1).trim()];
      }));
      resolve({ status: Number(statusLine.split(' ')[1]), headers, body: raw.slice(boundary + 4), raw });
    });
    socket.setTimeout(3000, () => socket.destroy(new Error('raw HTTP request timed out')));
  });
}
function request(port, target, { method = 'GET', headers = [host(port)], version = 'HTTP/1.1' } = {}) {
  return rawRequest(port, [`${method} ${target} ${version}`, ...headers, 'Connection: close']);
}
function host(port, value = `127.0.0.1:${port}`) { return `Host: ${value}`; }
function body(response) { return JSON.parse(response.body); }

async function start(root) {
  const dashboard = await startDashboard({ runs: root, port: 0 });
  return { dashboard, port: Number(new URL(dashboard.url).port) };
}

// This child is deliberately saved in the workspace work directory: it is a
// separate server process whose request phase runs with side-effect tripwires.
const tripwireChild = `
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import childProcess from 'node:child_process';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import readline from 'node:readline';
import { syncBuiltinESMExports } from 'node:module';
const [root, serverUrl] = process.argv.slice(2);
const { startDashboard } = await import(serverUrl);
const dashboard = await startDashboard({ runs: root, port: 0 });
const tripwire = (name) => function () {
  process.stderr.write('TRIPWIRE:' + name + '\\n');
  throw new Error('dashboard request attempted a forbidden side effect');
};
for (const name of ['access','accessSync','appendFile','appendFileSync','chmod','chmodSync','chown','chownSync','copyFile','copyFileSync','createReadStream','createWriteStream','existsSync','lstat','lstatSync','mkdir','mkdirSync','mkdtemp','mkdtempSync','open','openSync','opendir','opendirSync','read','readSync','readFile','readFileSync','readdir','readdirSync','readlink','readlinkSync','realpath','realpathSync','rename','renameSync','rm','rmSync','rmdir','rmdirSync','stat','statSync','symlink','symlinkSync','truncate','truncateSync','unlink','unlinkSync','write','writeSync','writeFile','writeFileSync']) if (typeof fs[name] === 'function') fs[name] = tripwire('fs.' + name);
for (const name of ['access','appendFile','chmod','chown','copyFile','lstat','mkdir','mkdtemp','open','opendir','readFile','readdir','readlink','realpath','rename','rm','rmdir','stat','symlink','truncate','unlink','writeFile']) if (typeof fsp[name] === 'function') fsp[name] = tripwire('fs.promises.' + name);
for (const name of ['exec','execFile','execFileSync','execSync','fork','spawn','spawnSync']) childProcess[name] = tripwire('child_process.' + name);
for (const name of ['connect','createConnection']) net[name] = tripwire('net.' + name);
for (const name of ['get','request']) http[name] = tripwire('http.' + name);
for (const name of ['get','request']) https[name] = tripwire('https.' + name);
tls.connect = tripwire('tls.connect');
globalThis.fetch = tripwire('fetch');
syncBuiltinESMExports();
process.stdout.write(JSON.stringify({ event: 'listening', url: dashboard.url }) + '\\n');
const input = readline.createInterface({ input: process.stdin });
for await (const line of input) {
  if (line !== 'close') continue;
  await dashboard.close();
  await dashboard.closed;
  break;
}
`;

async function waitForLine(stream, timeoutMs = 5000) {
  return await new Promise((resolve, reject) => {
    let pending = '';
    const timer = setTimeout(() => reject(new Error('timed out waiting for tripwire server startup')), timeoutMs);
    const onData = (chunk) => {
      pending += chunk.toString('utf8');
      const newline = pending.indexOf('\n');
      if (newline < 0) return;
      clearTimeout(timer);
      stream.off('data', onData);
      resolve(pending.slice(0, newline));
    };
    stream.on('data', onData);
    stream.on('error', (error) => { clearTimeout(timer); reject(error); });
  });
}

async function startTripwireChild(root, t) {
  await mkdir(workRoot, { recursive: true });
  const scriptPath = path.join(workRoot, `dashboard-security-tripwire-${process.pid}.mjs`);
  await writeFile(scriptPath, tripwireChild);
  t.after(async () => { await rm(scriptPath, { force: true }); });
  const child = spawn(process.execPath, [scriptPath, root, pathToFileURL(path.join(repo, 'src/dashboard/server.mjs')).href], { stdio: ['pipe', 'pipe', 'pipe'] });
  let stderr = '';
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => { stderr += chunk; });
  t.after(async () => {
    if (child.exitCode === null && !child.killed) child.kill('SIGKILL');
    if (child.exitCode === null) await new Promise((resolve) => child.once('exit', resolve));
  });
  const firstLine = await waitForLine(child.stdout);
  const event = JSON.parse(firstLine);
  assert.equal(event.event, 'listening');
  return { child, port: Number(new URL(event.url).port), stderr: () => stderr };
}

test('real HTTP requests enforce host, origin, raw-path, method, ID and query boundaries', async () => withFixture(async ({ root }) => {
  const { dashboard, port } = await start(root);
  try {
    const catalogResponse = await request(port, '/api/catalog');
    assert.equal(catalogResponse.status, 200);
    assert.equal(catalogResponse.headers['cache-control'], 'no-store');
    assert.equal(catalogResponse.headers['x-content-type-options'], 'nosniff');
    assert.equal(catalogResponse.headers['referrer-policy'], 'no-referrer');
    assert.match(catalogResponse.headers['content-security-policy'], /default-src 'none'/);
    const catalog = body(catalogResponse);
    const baseId = catalog.artifacts.find((item) => item.kind === 'run' && item.label === 'run.json').id;
    const currentId = catalog.artifacts.find((item) => item.kind === 'run' && item.label === 'current/run.json').id;
    const comparisonId = catalog.artifacts.find((item) => item.kind === 'comparison').id;
    const unknownId = 'f'.repeat(64);

    assert.equal((await request(port, '/api/catalog', { headers: [], version: 'HTTP/1.0' })).status, 403, 'missing Host');
    assert.equal((await request(port, '/api/catalog', { headers: [host(port), host(port)] })).status, 403, 'duplicate Host');
    assert.equal((await request(port, '/api/catalog', { headers: [host(port, `127.0.0.1:${port + 1}`)] })).status, 403, 'wrong Host port');
    assert.equal((await request(port, '/api/catalog', { headers: [host(port, `localhost:${port}`), `Origin: http://localhost:${port}`] })).status, 200, 'accepted localhost authority and matching origin');
    assert.equal((await request(port, '/api/catalog', { headers: [host(port), 'Origin: http://evil.example'] })).status, 403, 'foreign Origin');
    assert.equal((await request(port, '/api/catalog', { headers: [host(port), 'Origin: null'] })).status, 403, 'null Origin');
    assert.equal((await request(port, '/api/catalog', { headers: [host(port), `Origin: http://127.0.0.1:${port}`, `Origin: http://127.0.0.1:${port}`] })).status, 403, 'duplicate Origin');
    assert.equal((await request(port, '/api/catalog', { headers: [host(port), 'Sec-Fetch-Site: cross-site'] })).status, 403, 'cross-site fetch metadata');
    assert.equal((await request(port, '/api/catalog', { headers: [host(port, `127.0.0.1.:${port}`)] })).status, 403, 'trailing-dot Host');

    for (const target of [
      '/%2e%2e/api/catalog',
      '/api/%2fcatalog',
      '/api/../api/catalog',
      '/api/./catalog',
      '/api//catalog',
      '/api\\catalog',
      `http://127.0.0.1:${port}/api/catalog`,
      '/api/catalog#fragment',
    ]) {
      const response = await request(port, target);
      assert.equal(response.status, 400, `raw target ${target}`);
    }
    assert.equal((await request(port, '/api/catalog?unexpected=1')).status, 400, 'query is route-specific');
    assert.equal((await request(port, '/missing')).status, 404, 'unknown route');
    const post = await request(port, '/api/catalog', { method: 'POST' });
    assert.equal(post.status, 405);
    assert.equal(post.headers.allow, 'GET, HEAD');
    const options = await request(port, '/api/catalog', { method: 'OPTIONS' });
    assert.equal(options.status, 405);
    assert.equal(options.headers['access-control-allow-origin'], undefined);
    assert.equal((await request(port, '/api/compare', { method: 'HEAD' })).status, 405, 'comparison is GET only');
    const head = await request(port, '/api/catalog', { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.body, '', 'HEAD sends no body');
    assert.ok(Number(head.headers['content-length']) > 0, 'HEAD retains GET content length');

    assert.equal((await request(port, `/api/artifacts/${unknownId}`)).status, 404, 'unknown artifact ID');
    assert.equal((await request(port, '/api/compare?baseline=bad&current=bad')).status, 400, 'malformed IDs');
    assert.equal((await request(port, `/api/compare?current=${currentId}`)).status, 400, 'missing baseline');
    assert.equal((await request(port, `/api/compare?baseline=${baseId}&current=${currentId}&baseline=${baseId}`)).status, 400, 'duplicate ID parameter');
    assert.equal((await request(port, `/api/compare?baseline=${baseId}&current=${currentId}&failOn=high&failOn=none`)).status, 400, 'duplicate threshold');
    assert.equal((await request(port, `/api/compare?baseline=${baseId}&current=${currentId}&unexpected=x`)).status, 400, 'unknown query parameter');
    assert.equal((await request(port, `/api/compare?baseline=${baseId}&current=${currentId}&failOn=bogus`)).status, 400, 'unsupported threshold');
    assert.equal((await request(port, `/api/compare?baseline=${unknownId}&current=${currentId}`)).status, 404, 'unknown comparison ID');
    assert.equal((await request(port, `/api/compare?baseline=${comparisonId}&current=${currentId}`)).status, 422, 'comparison artifact is not a run input');

    const defaultComparison = body(await request(port, `/api/compare?baseline=${baseId}&current=${currentId}`));
    assert.equal(defaultComparison.comparison.gate.failOn, 'high');
    assert.equal(defaultComparison.comparison.gate.exitCode, 1);
    const anyComparison = body(await request(port, `/api/compare?baseline=${baseId}&current=${currentId}&failOn=any`));
    assert.equal(anyComparison.comparison.gate.failOn, 'any');
    assert.equal(anyComparison.comparison.gate.exitCode, 1);
    const noneComparison = body(await request(port, `/api/compare?baseline=${baseId}&current=${currentId}&failOn=none`));
    assert.equal(noneComparison.comparison.gate.failOn, 'none');
    assert.equal(noneComparison.comparison.gate.exitCode, 0);
  } finally {
    await dashboard.close();
    await dashboard.closed;
  }
}));

test('HTTP request handlers perform no filesystem, child-process or outbound-network operations after startup', async (t) => withFixture(async ({ root }) => {
  const { child, port, stderr } = await startTripwireChild(root, t);
  const catalog = body(await request(port, '/api/catalog'));
  const baseline = catalog.artifacts.find((entry) => entry.kind === 'run' && entry.label === 'run.json').id;
  const current = catalog.artifacts.find((entry) => entry.kind === 'run' && entry.label === 'current/run.json').id;
  const paths = [
    '/api/catalog',
    `/api/artifacts/${baseline}`,
    `/api/compare?baseline=${baseline}&current=${current}`,
    '/',
    '/assets/app.mjs',
    '/unknown',
  ];
  for (const target of paths) {
    const response = await request(port, target);
    assert.ok([200, 404].includes(response.status), `${target} unexpectedly returned ${response.status}`);
  }
  assert.equal(stderr(), '', 'no post-start tripwire operation was attempted');
  child.stdin.end('close\n');
  const exit = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => resolve({ code, signal }));
    setTimeout(() => reject(new Error('tripwire server did not exit after close')), 5000).unref();
  });
  assert.deepEqual(exit, { code: 0, signal: null });
  assert.equal(stderr(), '', 'server shutdown did not trigger a tripwire');
}));
