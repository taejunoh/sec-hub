import test from 'node:test';
import assert from 'node:assert/strict';
import fsPromises from 'node:fs/promises';
import http from 'node:http';
import { syncBuiltinESMExports } from 'node:module';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import { main } from '../src/cli.mjs';
import { startDashboard } from '../src/dashboard/server.mjs';

async function withRoot(callback) {
  const root = await mkdtemp(path.join(os.tmpdir(), 'sec-hub-dashboard-lifecycle-'));
  try { return await callback(root); } finally { await rm(root, { recursive: true, force: true }); }
}

test('abort during asynchronous startup rejects without ever attaching a listener', async () => withRoot(async (root) => {
  const originalLstat = fsPromises.lstat;
  const originalListen = http.Server.prototype.listen;
  let releaseAssetLoad;
  let assetLoadStarted;
  const assetLoading = new Promise((resolve) => { assetLoadStarted = resolve; });
  const assetGate = new Promise((resolve) => { releaseAssetLoad = resolve; });
  let listenerCalls = 0;

  fsPromises.lstat = async (filename, ...args) => {
    if (String(filename).includes(`${path.sep}src${path.sep}web${path.sep}`)) {
      assetLoadStarted();
      await assetGate;
    }
    return originalLstat(filename, ...args);
  };
  http.Server.prototype.listen = function (...args) {
    listenerCalls += 1;
    return originalListen.apply(this, args);
  };
  syncBuiltinESMExports();

  const controller = new AbortController();
  const startup = startDashboard({ runs: root, signal: controller.signal });
  try {
    await assetLoading;
    controller.abort();
    releaseAssetLoad();
    await assert.rejects(startup, /aborted/i);
    assert.equal(listenerCalls, 0, 'startup must stop before calling server.listen');
  } finally {
    releaseAssetLoad();
    fsPromises.lstat = originalLstat;
    http.Server.prototype.listen = originalListen;
    syncBuiltinESMExports();
  }
}));

test('runtime listener failure rejects closed and makes serve return 2 with a constant diagnostic', async () => withRoot(async (root) => {
  const originalCreateServer = http.createServer;
  let capturedServer;
  const injectFailure = () => {
    http.createServer = (...args) => {
      capturedServer = originalCreateServer(...args);
      capturedServer.once('listening', () => {
        setImmediate(() => capturedServer.emit('error', new Error('synthetic private failure')));
      });
      return capturedServer;
    };
    syncBuiltinESMExports();
  };
  const restore = () => {
    http.createServer = originalCreateServer;
    syncBuiltinESMExports();
  };

  try {
    injectFailure();
    const dashboard = await startDashboard({ runs: root });
    await assert.rejects(dashboard.closed, /Dashboard server failed/);
    await dashboard.close();
    assert.ok(capturedServer, 'failure was injected into the listening server');

    capturedServer = undefined;
    injectFailure();
    let stdout = '';
    let stderr = '';
    const code = await main(['serve', '--runs', root], {
      stdout: { write: (value) => { stdout += value; } },
      stderr: { write: (value) => { stderr += value; } },
    });
    assert.equal(code, 2);
    assert.match(stdout, /"event":"listening"/);
    assert.equal(stderr, 'sec-hub: Dashboard server failed.\n');
    assert.ok(capturedServer, 'CLI failure was injected after listening');
  } finally {
    restore();
  }
}));

test('production JSON serializer rejects a body just over 64 MiB with HTTP 413 metadata', async () => {
  const serverSource = await readFile(new URL('../src/dashboard/server.mjs', import.meta.url), 'utf8');
  const start = serverSource.indexOf('function jsonBuffer(');
  const end = serverSource.indexOf('function errorBody(', start);
  assert.ok(start >= 0 && end > start, 'the private serializer source is present');
  const serializerSource = `${serverSource.slice(start, end)}\nthis.serializeJson = jsonBuffer;`;
  const production = { Buffer, RESPONSE_LIMIT: 64 * 1024 * 1024 };
  runInNewContext(serializerSource, production);

  assert.throws(() => production.serializeJson('x'.repeat(64 * 1024 * 1024)), (error) => {
    assert.equal(error.status, 413);
    assert.equal(error.code, 'response_too_large');
    return true;
  });
});
