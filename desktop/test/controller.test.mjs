import test from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { startDashboard } from '../../src/dashboard/server.mjs';
import { spawn } from 'node:child_process';
const api = await import('../app/controller.mjs').catch(() => ({}));
const smokeApi = await import('../app/smoke.mjs').catch(() => ({}));
const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };

function harness(overrides = {}) {
  assert.equal(typeof api.createViewerController, 'function', 'viewer lifecycle controller must exist');
  const starts = [], views = [], notices = [], servers = [];
  const controller = api.createViewerController({
    sampleRuns: '/synthetic/example',
    startDashboard: async (options) => {
      starts.push(options);
      const server = createServer((req, res) => { res.setHeader('Connection', 'close'); res.end('saved result'); });
      server.listen(0, '127.0.0.1'); await once(server, 'listening');
      const record = { url: `http://127.0.0.1:${server.address().port}/`, closes: 0, close: async () => { record.closes++; await new Promise((resolve) => server.close(resolve)); } };
      servers.push(record); return record;
    },
    inspectDashboard: async () => ({ readyCount: 1 }),
    show: async (view) => { views.push(view); },
    notify: async (message) => { notices.push(message); },
    ...overrides,
  });
  return { controller, starts, views, notices, servers };
}

test('sample startup is read only, labeled, and owns a real listening server', async () => {
  const h = harness();
  try {
    await h.controller.showExample();
    assert.equal(h.views[0].example, true);
    assert.equal(h.starts[0].runs, '/synthetic/example');
    assert.deepEqual(Object.keys(h.starts[0]).sort(), ['port', 'runs', 'signal']);
    assert.equal(h.starts[0].port, 0);
    assert.ok(h.starts[0].signal instanceof AbortSignal);
    assert.equal((await fetch(h.controller.current.url)).status, 200);
  } finally { await h.controller.close(); }
  await assert.rejects(fetch(h.servers[0].url));
});

test('a successful folder change replaces the view and closes the old listener', async () => {
  const h = harness();
  try {
    await h.controller.showExample(); const old = h.controller.current.url;
    await h.controller.showFolder('/chosen/results');
    assert.equal(h.controller.current.example, false);
    assert.equal(h.starts[1].runs, '/chosen/results');
    assert.equal(h.servers[0].closes, 1);
    await assert.rejects(fetch(old));
    assert.equal((await fetch(h.controller.current.url)).status, 200);
  } finally { await h.controller.close(); }
});

test('empty, invalid and failed folder changes retain the old usable view', async () => {
  let readyCount = 1;
  const h = harness({ inspectDashboard: async () => { if (readyCount === -1) throw Error('private path must not leak'); return { readyCount }; } });
  try {
    await h.controller.showExample(); const old = h.controller.current.url;
    for (readyCount of [0, -1]) {
      assert.equal(await h.controller.showFolder('/chosen/bad'), false);
      assert.equal(h.controller.current.url, old);
      assert.equal(h.views.length, 1);
      assert.equal((await fetch(old)).status, 200);
    }
    assert.equal(h.notices.length, 2);
    assert.ok(h.notices.every((message) => !message.includes('private')));
    assert.equal(h.servers[1].closes, 1); assert.equal(h.servers[2].closes, 1);
  } finally { await h.controller.close(); }
});

test('concurrent changes are serialized and closing prevents queued changes', async () => {
  const hold = deferred(), entered = deferred(); let inspections = 0;
  const h = harness({ inspectDashboard: async () => { if (++inspections === 1) { entered.resolve(); await hold.promise; } return { readyCount: 1 }; } });
  const start = h.controller.showExample(); await entered.promise;
  const queued = h.controller.showFolder('/queued/results');
  const closing = h.controller.close(); hold.resolve();
  await Promise.all([start, queued, closing]);
  assert.equal(h.starts.length, 1); assert.equal(h.views.length, 0);
  assert.equal(h.controller.current, null); assert.equal(h.servers[0].closes, 1);
});

test('quit joins a delayed startup even if startup ignores cancellation', async () => {
  const hold = deferred(), entered = deferred(); let closed = 0, signal;
  const h = harness({ startDashboard: async (options) => { signal = options.signal; entered.resolve(); await hold.promise; return { url: 'http://127.0.0.1:43210/', close: async () => { closed++; } }; } });
  const start = h.controller.showExample(); await entered.promise;
  const close = h.controller.close(); assert.equal(signal.aborted, true);
  let settled = false; void close.then(() => { settled = true; });
  await Promise.resolve(); assert.equal(settled, false);
  hold.resolve(); await Promise.all([start, close]);
  assert.equal(closed, 1); assert.equal(h.views.length, 0);
  await h.controller.close(); assert.equal(closed, 1);
});

test('a failed renderer switch restores the prior view and closes the candidate', async () => {
  const views = [];
  const h = harness({ show: async (view) => { views.push(view); if (!view.example) throw Error('load failure'); } });
  try {
    await h.controller.showExample(); const old = h.controller.current.url;
    assert.equal(await h.controller.showFolder('/chosen/results'), false);
    assert.equal(h.controller.current.url, old);
    assert.equal(views.at(-1).url, old);
    assert.equal(h.servers[1].closes, 1);
  } finally { await h.controller.close(); }
});

test('bundled synthetic example is canonical and exposes no execution or raw source', async () => {
  const root = fileURLToPath(new URL('../app/sample/example/', import.meta.url));
  const sample = JSON.parse(await readFile(new URL('../app/sample/example/run.json', import.meta.url)));
  assert.equal(sample.findings.length, 3);
  const forbidden = new Set(['rawRef', 'rawRefs', 'sourceRecords']);
  function inspect(value) {
    if (!value || typeof value !== 'object') return;
    for (const [key, item] of Object.entries(value)) { assert.equal(forbidden.has(key), false); inspect(item); }
  }
  inspect(sample);
  const server = await startDashboard({ runs: root, port: 0 });
  try {
    const catalog = await (await fetch(`${server.url}api/catalog`)).json();
    assert.equal(catalog.artifacts.filter((item) => item.state === 'ready').length, 1);
    assert.equal(catalog.artifacts[0].summary.findingCount, 3);
    assert.equal((await fetch(`${server.url}api/execution`)).status, 404);
  } finally { await server.close(); }
});

test('native actions accept only the picker result and open only the current owned URL', async () => {
  assert.equal(typeof api.createNativeActions, 'function');
  const h = harness(); let choice; const opened = [];
  const actions = api.createNativeActions({ controller: h.controller, pickFolder: async () => choice, openExternal: async (url) => opened.push(url) });
  try {
    await actions.openInBrowser('https://evil.test/'); assert.equal(opened.length, 0);
    await h.controller.showExample();
    await actions.openSavedResults(); assert.equal(h.starts.length, 1);
    choice = '/native/picked/folder'; await actions.openSavedResults('/arbitrary/renderer');
    assert.equal(h.starts.at(-1).runs, '/native/picked/folder');
    await actions.openInBrowser('https://evil.test/');
    assert.deepEqual(opened, [h.controller.current.url]);
  } finally { await h.controller.close(); }
});

test('failed smoke cleanup joins even a secondary process that ignores termination', async () => {
  assert.equal(typeof smokeApi.stopSecondary, 'function');
  const child = spawn(process.execPath, ['-e', "process.on('SIGTERM',()=>{});process.stdout.write('ready');setInterval(()=>{},1000)"], { stdio: ['ignore', 'pipe', 'ignore'] });
  const exited = once(child, 'exit');
  try {
    await once(child.stdout, 'data');
    await smokeApi.stopSecondary(child, exited);
    assert.ok(child.exitCode !== null || child.signalCode !== null);
    await exited;
  } finally { if (child.exitCode === null && child.signalCode === null) { child.kill('SIGKILL'); await exited; } }
});
