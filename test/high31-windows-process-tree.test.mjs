import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runProcess } from '../src/processes.mjs';

// Only the OS process boundary is simulated. runProcess and its timers/events are real.
async function windowsFixture(t, { helper = 'success', root = 'C:\\Windows' } = {}) {
  const platform = Object.getOwnPropertyDescriptor(process, 'platform');
  const originalSpawn = childProcess.spawn;
  const previousRoot = process.env.SystemRoot;
  Object.defineProperty(process, 'platform', { value: 'win32', configurable: true });
  if (root === undefined) delete process.env.SystemRoot; else process.env.SystemRoot = root;
  const calls = [], signals = [];
  let leaderAlive = true, descendantAlive = true, helperFinished = false, helperKilled = false;
  const leader = new EventEmitter();
  Object.assign(leader, { pid: 4312, stdout: new PassThrough(), stderr: new PassThrough(), unref() {}, kill(kind) { signals.push(kind); closeLeader(); return true; } });
  function closeLeader() { if (leaderAlive) { leaderAlive = false; leader.emit('close', null); } }
  childProcess.spawn = (command, args, options) => {
    calls.push({ command, args, options });
    if (calls.length === 1) return leader;
    const killer = new EventEmitter();
    Object.assign(killer, { kill() { helperKilled = true; return true; }, unref() {} });
    if (helper === 'error') queueMicrotask(() => killer.emit('error', Object.assign(new Error('fixture'), { code: 'ENOENT' })));
    else if (helper === 'nonzero') queueMicrotask(() => killer.emit('close', 5));
    else if (helper === 'success') {
      // Tree lookup must happen before any independent leader kill. Close the
      // leader early, then finish descendant cleanup later than POSIX escalation.
      const capturedTree = leaderAlive;
      closeLeader();
      const timer = setTimeout(() => { if (capturedTree) descendantAlive = false; helperFinished = true; killer.emit('close', 0); }, 420);
      t.after(() => clearTimeout(timer));
    }
    return killer;
  };
  syncBuiltinESMExports();
  t.after(() => {
    childProcess.spawn = originalSpawn; syncBuiltinESMExports();
    Object.defineProperty(process, 'platform', platform);
    if (previousRoot === undefined) delete process.env.SystemRoot; else process.env.SystemRoot = previousRoot;
    leader.stdout.destroy(); leader.stderr.destroy();
  });
  return { leader, calls, signals, get descendantAlive() { return descendantAlive; }, get helperFinished() { return helperFinished; }, get helperKilled() { return helperKilled; } };
}

for (const trigger of ['timeout', 'cancel', 'output-limit']) {
  test(`Windows simulation: ${trigger} waits for whole-tree cleanup after leader closes`, async t => {
    const f = await windowsFixture(t);
    const controller = new AbortController();
    const pending = runProcess({ command: 'fixture.exe', args: ['literal & argument'], cwd: 'C:\\untrusted' }, {
      timeoutMs: trigger === 'timeout' ? 10 : 5000, signal: controller.signal, maxOutputBytes: 8,
      env: { SystemRoot: 'C:\\untrusted', PATH: 'C:\\untrusted' }
    });
    if (trigger === 'cancel') controller.abort();
    if (trigger === 'output-limit') f.leader.stdout.write('too much output');
    const result = await pending;
    assert.equal(f.descendantAlive, false, 'descendant must stop before runProcess resolves');
    assert.equal(f.helperFinished, true, 'leader close must not settle before asynchronous taskkill completion');
    assert.deepEqual(f.signals, [], 'do not kill leader before taskkill discovers its tree');
    assert.equal(f.calls.length, 2, 'one tree kill request, no delayed PID reuse');
    assert.equal(f.calls[1].command, 'C:\\Windows\\System32\\taskkill.exe');
    assert.deepEqual(f.calls[1].args, ['/PID', '4312', '/T', '/F']);
    assert.equal(f.calls[1].options.shell, false);
    assert.equal(f.calls[1].options.windowsHide, true);
    assert.equal(f.calls[1].options.stdio, 'ignore');
    assert.notEqual(f.calls[1].options.cwd, 'C:\\untrusted');
    assert.notEqual(f.calls[1].options.env?.SystemRoot, 'C:\\untrusted');
    assert.equal(result.status, { timeout: 'timed_out', cancel: 'cancelled', 'output-limit': 'failed' }[trigger]);
    if (trigger === 'output-limit') assert.equal(result.stdout, '');
  });
}

for (const helper of ['error', 'nonzero', 'hang']) {
  test(`Windows simulation: ${helper} tree killer is bounded and reports unconfirmed cleanup`, async t => {
    const f = await windowsFixture(t, { helper });
    const controller = new AbortController();
    const pending = runProcess({ command: 'fixture.exe', args: [] }, { signal: controller.signal });
    controller.abort();
    const result = await pending;
    assert.match(result.reason, /Windows process-tree cleanup .*not confirmed/);
    assert.ok(result.durationMs < 2500);
    assert.equal(result.status, 'cancelled');
    if (helper === 'hang') assert.equal(f.helperKilled, true, 'bounded cleanup also stops the taskkill helper');
  });
}

test('Windows simulation: invalid system root cannot invoke a PATH executable', async t => {
  const f = await windowsFixture(t, { root: 'relative\\attacker' });
  const controller = new AbortController();
  const pending = runProcess({ command: 'fixture.exe', args: [] }, { signal: controller.signal });
  controller.abort();
  const result = await pending;
  assert.equal(f.calls.length, 1);
  assert.match(result.reason, /Windows process-tree cleanup .*not confirmed/);
});

test('Windows native: timeout terminates descendant heartbeat', { skip: process.platform !== 'win32' }, async t => {
  const directory = await mkdtemp(join(tmpdir(), 'sec-hub-high31-'));
  const heartbeat = join(directory, 'heartbeat'), pidFile = join(directory, 'pid');
  let pid;
  t.after(async () => {
    if (!pid) try { pid = Number(await readFile(pidFile, 'utf8')); } catch {}
    if (pid) try { process.kill(pid, 'SIGKILL'); } catch {}
    await rm(directory, { recursive: true, force: true });
  });
  const worker = 'const fs=require("node:fs");fs.writeFileSync(process.argv[2],String(process.pid));setInterval(()=>fs.appendFileSync(process.argv[1],"x"),10)';
  const leader = 'require("node:child_process").spawn(process.execPath,["-e",process.argv[1],process.argv[2],process.argv[3]],{stdio:"ignore"});setInterval(()=>{},1000)';
  const result = await runProcess({ command: process.execPath, args: ['-e', leader, worker, heartbeat, pidFile] }, { timeoutMs: 1500 });
  pid = Number(await readFile(pidFile, 'utf8'));
  assert.equal(result.status, 'timed_out');
  assert.doesNotMatch(result.reason, /not confirmed/);
  const before = await readFile(heartbeat, 'utf8');
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.equal(await readFile(heartbeat, 'utf8'), before);
});
