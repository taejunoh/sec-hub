import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, mkdir, writeFile, rm, realpath } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { once } from 'node:events';

const cli = new URL('../bin/sec-hub.mjs', import.meta.url);
// Without CLI plumbing a valid manifest silently leaves execution disabled.
test('serve opt-in prints an operator session launch event and exits cleanly on signal', async () => {
  const root = await mkdtemp(path.join(await realpath(tmpdir()), 'sec-hub-serve-execution-'));
  const runs = path.join(root, 'runs'), target = path.join(root, 'target'), config = path.join(root, 'scanner.json'), manifest = path.join(root, 'execution.json');
  await mkdir(runs); await mkdir(target);
  await writeFile(config, '{"tools":{}}');
  await writeFile(manifest, JSON.stringify({ schemaVersion: 1, targets: [{ label: 'CLI fixture', path: target, config, tools: ['osv'], ai: false, timeoutMs: 5000 }] }));
  const child = spawn(process.execPath, [cli.pathname, 'serve', '--runs', runs, '--execution-config', manifest], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = '', stdout = ''; child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; }); child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
  const exited = once(child, 'exit');
  try {
    await Promise.race([
      new Promise((resolve, reject) => {
        const onData = () => { if (stdout.includes('\n')) { child.stdout.off('data', onData); resolve(); } };
        child.stdout.on('data', onData);
        exited.then(() => { if (!stdout.includes('\n')) reject(new Error('no listening event')); });
      }),
      new Promise((_, reject) => { setTimeout(() => reject(new Error('startup deadline')), 5000).unref(); }),
    ]);
    const started = JSON.parse(stdout.trim());
    assert.equal(started.event, 'listening'); assert.equal(started.readOnly, false);
    assert.equal(new URL(started.executionUrl).origin, new URL(started.url).origin);
    assert.match(new URL(started.executionUrl).hash, /^#session=[a-f0-9]{64}$/);
    child.kill('SIGTERM'); const [code] = await exited;
    assert.equal(code, 0); assert.equal(stderr, ''); assert.equal(stdout.trim().split('\n').length, 1);
  } finally { if (child.exitCode === null) { child.kill('SIGKILL'); await exited; } await rm(root, { recursive: true, force: true }); }
});
