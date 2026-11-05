import test from 'node:test';
import assert from 'node:assert/strict';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { copyFile, mkdir, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runProcess } from '../src/processes.mjs';
import { pathToFileURL } from 'node:url';

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

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function alive(pid) {
  try { process.kill(pid, 0); return true; }
  catch (error) { if (error.code === 'ESRCH') return false; throw error; }
}

for (const trigger of ['timeout', 'cancel', 'output-limit']) {
  test(`Windows native: ${trigger} terminates a ready descendant heartbeat`, { skip: process.platform !== 'win32', timeout: 15000 }, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'sec-hub-high31-'));
    const heartbeat = join(directory, 'heartbeat'), pidFile = join(directory, 'pid'), floodGate = join(directory, 'flood');
    const controller = new AbortController();
    let pids, pending;
    try {
      const worker = 'const fs=require("node:fs");fs.writeFileSync(process.argv[2],JSON.stringify([process.pid,process.ppid]));fs.writeFileSync(process.argv[1],"x");setInterval(()=>fs.appendFileSync(process.argv[1],"x"),20)';
      const leader = 'const fs=require("node:fs");require("node:child_process").spawn(process.execPath,["-e",process.argv[1],process.argv[2],process.argv[3]],{stdio:"ignore"});setInterval(()=>{if(fs.existsSync(process.argv[4]))process.stdout.write("x".repeat(4096));},20)';
      pending = runProcess({ command: process.execPath, args: ['-e', leader, worker, heartbeat, pidFile, floodGate] }, {
        timeoutMs: trigger === 'timeout' ? 5000 : 10000, signal: controller.signal, maxOutputBytes: 64,
      });
      const readyDeadline = Date.now() + 3500;
      let first;
      while (Date.now() < readyDeadline) {
        try {
          pids = JSON.parse(await readFile(pidFile, 'utf8'));
          first = await readFile(heartbeat, 'utf8');
          if (first.length >= 3) break;
        } catch (error) { if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error; }
        await pause(25);
      }
      assert.ok(Array.isArray(pids) && pids.length === 2 && pids.every(pid => Number.isSafeInteger(pid) && pid > 0), 'descendant and leader PIDs are ready');
      assert.ok(first?.length >= 3, 'descendant produced multiple heartbeats before termination');
      assert.ok(pids.every(alive), 'both real processes are alive before the trigger');
      await pause(100);
      assert.ok((await readFile(heartbeat, 'utf8')).length > first.length, 'heartbeat grows before the trigger');
      if (trigger === 'cancel') controller.abort();
      if (trigger === 'output-limit') await writeFile(floodGate, 'start');
      const result = await pending;
      assert.equal(result.status, { timeout: 'timed_out', cancel: 'cancelled', 'output-limit': 'failed' }[trigger]);
      assert.doesNotMatch(result.reason, /not confirmed/);
      if (trigger === 'output-limit') {
        assert.match(result.reason, /Output exceeds 64 byte limit/);
        assert.equal(result.stdout, '');
      }
      const before = await readFile(heartbeat, 'utf8');
      await pause(250);
      assert.equal(await readFile(heartbeat, 'utf8'), before, 'observed live descendant heartbeat stops');
      assert.ok(pids.every(pid => !alive(pid)), 'leader and descendant PIDs are no longer alive');
    } finally {
      controller.abort();
      await pending;
      if (!pids) try { pids = JSON.parse(await readFile(pidFile, 'utf8')); } catch {}
      for (const pid of pids ?? []) if (Number.isSafeInteger(pid) && pid > 0) try { process.kill(pid, 'SIGKILL'); } catch {}
      await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
    }
  });
}

test('Windows native: unsupported ACL trust rejects writes before mutation', { skip: process.platform !== 'win32' }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sec-hub-win-acl-'));
  try {
    const isolated = join(directory, 'module');
    await mkdir(isolated);
    for (const name of ['safe-io.mjs', 'safe-io-windows.mjs']) {
      await copyFile(new URL('../src/' + name, import.meta.url), join(isolated, name));
    }
    const safe = await import(pathToFileURL(join(isolated, 'safe-io.mjs')).href);
    await assert.rejects(safe.ensureSafeDirectory(join(directory, 'new')), /ACL helper.*unavailable/i);
    await assert.rejects(safe.atomicWriteFile(join(directory, 'report'), 'synthetic'), /ACL helper.*unavailable/i);
    assert.deepEqual(await readdir(directory), ['module']);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
