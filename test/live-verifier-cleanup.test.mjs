import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { runFiveToolVerification } from '../scripts/live-verify-five.mjs';
import { atomicWriteFile } from '../src/safe-io.mjs';

const scanOptions = {
  'codex-security': { auth: 'chatgpt', model: 'gpt-6.1-sol', effort: 'medium', maxCost: 2, maxTimeMinutes: 3 },
  'open-code-review': { provider: 'chatgpt', model: 'gpt-6.1-sol', maxTokensBudget: 20000, concurrency: 1, timeoutMinutes: 3 },
};

async function runInjectedFailure({ failEvidenceWrite = false, failSummaryWrite = false } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'live-verifier-cleanup-'));
  const out = path.join(directory, 'out');
  let fixtureClosed = false;
  const listenersBefore = { sigint: process.listenerCount('SIGINT'), sigterm: process.listenerCount('SIGTERM') };
  const runProcessImpl = async ({ command, args }) => {
    if (args[0] === '--version') return { status: 'completed', exitCode: 0, stdout: 'v24.22.1\n', stderr: '' };
    if (command === 'git') return { status: 'completed', exitCode: 0, stdout: '', stderr: '' };
    if (args[1] === 'doctor') {
      await rm(args[2], { recursive: true });
      return { status: 'failed', exitCode: 1, stdout: '', stderr: 'synthetic doctor failure' };
    }
    throw new Error('Unexpected subprocess in cleanup test');
  };
  const atomicWriteFileImpl = async (filename, contents, options) => {
    if (failEvidenceWrite && filename.endsWith('verification-commands.json')) throw new Error('synthetic evidence write failure');
    if (failSummaryWrite && filename.endsWith('LIVE-VERIFICATION.md')) throw new Error('synthetic summary write failure');
    return atomicWriteFile(filename, contents, options);
  };
  const code = await runFiveToolVerification({
    argv: ['--config', path.join(directory, 'synthetic.config.json'), '--out', out],
    loadConfigImpl: async () => ({ tools: Object.fromEntries(Object.entries(scanOptions).map(([id, options]) => [id, { scanOptions: options }])) }),
    runProcessImpl,
    startFixtureImpl: async () => ({ url: 'http://127.0.0.1:1', close: async () => { fixtureClosed = true; } }),
    atomicWriteFileImpl,
  });
  const listenersAfter = { sigint: process.listenerCount('SIGINT'), sigterm: process.listenerCount('SIGTERM') };
  return { directory, out, code, fixtureClosed, listenersBefore, listenersAfter };
}

test('post-scan target hash failure still closes fixture and persists failed evidence', async () => {
  const result = await runInjectedFailure();
  try {
    assert.equal(result.code, 2);
    assert.equal(result.fixtureClosed, true);
    assert.deepEqual(result.listenersAfter, result.listenersBefore);
    const evidence = JSON.parse(await readFile(path.join(result.out, 'verification-commands.json'), 'utf8'));
    assert.equal(evidence.verificationPassed, false);
    assert.match(evidence.error, /Doctor failed/);
    assert.ok(evidence.finalizationErrors.some(error => error.startsWith('Target hash collection failed:')));
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test('evidence write failure does not skip fixture shutdown, summary attempt, or listener removal', async () => {
  const result = await runInjectedFailure({ failEvidenceWrite: true });
  try {
    assert.equal(result.code, 2);
    assert.equal(result.fixtureClosed, true);
    assert.deepEqual(result.listenersAfter, result.listenersBefore);
    const summary = await readFile(path.join(result.out, 'LIVE-VERIFICATION.md'), 'utf8');
    assert.match(summary, /Verification evidence write failed: synthetic evidence write failure/);
    assert.match(summary, /Verification passed: false/);
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});

test('summary-only write failure refreshes persisted machine evidence as failed', async () => {
  const result = await runInjectedFailure({ failSummaryWrite: true });
  try {
    assert.equal(result.code, 2);
    assert.equal(result.fixtureClosed, true);
    assert.deepEqual(result.listenersAfter, result.listenersBefore);
    const evidence = JSON.parse(await readFile(path.join(result.out, 'verification-commands.json'), 'utf8'));
    assert.equal(evidence.verificationPassed, false);
    assert.ok(evidence.finalizationErrors.some(error => error.startsWith('Verification summary write failed: synthetic summary write failure')));
  } finally {
    await rm(result.directory, { recursive: true, force: true });
  }
});
