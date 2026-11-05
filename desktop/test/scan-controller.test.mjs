import test from 'node:test';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { access, mkdtemp, mkdir, readFile, realpath, rename, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/runner.mjs';
import { startDashboard } from '../../src/dashboard/server.mjs';
import { createDesktopScanController } from '../../src/dashboard/desktop-execution.mjs';
import { isTrustedSender } from '../app/policy.mjs';

const sample = new URL('../app/sample/example/', import.meta.url);
const samplePath = fileURLToPath(sample);
const token = 'a'.repeat(64);

async function fixture(t, options = {}) {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'sec-hub-desktop-host-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const target = join(root, 'chosen');
  const runs = join(root, 'runs');
  await mkdir(target);
  let chosen = target;
  const scans = [];
  const base = {
    runs, pickFolder: async () => chosen,
    inspectTools: async () => [
      { id: 'osv', ai: false, command: join(root, 'bundled-osv'), installation: 'installed' },
      { id: 'open-code-review', ai: true, command: join(root, 'trusted-ocr'), installation: 'installed', setup: { sign_in: 'https://github.com/alibaba/open-code-review' } },
      { id: 'codex-security', ai: true, installation: 'unknown' },
    ],
    confirmAI: async () => false,
    openExternal: async () => {},
    scan: async (input) => { scans.push(input); return { id: 'run-test', status: 'completed', directory: input.out }; },
    report: async () => {},
  };
  const host = await createDesktopScanController({ ...base, ...options });
  t.after(() => host.close());
  return { host, root, target, runs, scans, setChoice: (value) => { chosen = value; } };
}

test('the native picker is the only source of a target, and state contains no executable or absolute path', async (t) => {
  const { host, target, scans } = await fixture(t);
  assert.deepEqual(await host.startScan({ toolIds: ['osv'], aiConsent: false }), { error: { code: 'target_not_found' } });
  const state = await host.chooseFolder();
  assert.equal(state.folderLabel, 'chosen');
  assert.deepEqual(state.tools[0], { id: 'osv', installation: 'installed', authentication: 'not_required', selectable: true, ai: false });
  assert.ok(!JSON.stringify(state).includes(target));
  assert.deepEqual(await host.startScan({ toolIds: ['osv'], aiConsent: false, path: target }), { error: { code: 'invalid_request' } });
  const result = await host.startScan({ toolIds: ['osv'], aiConsent: false });
  assert.equal(result.job.targetLabel, 'chosen');
  await host.close();
  assert.equal(scans.length, 0, 'shutdown cancels work before the guarded scan starts');
});

test('the host rechecks directory identity before executing and rejects overlapping run locations', async (t) => {
  const { host, target, root, runs, setChoice } = await fixture(t);
  await host.chooseFolder();
  for (const forbidden of [root, runs]) {
    setChoice(forbidden);
    assert.deepEqual(await host.chooseFolder(), { error: { code: 'target_unavailable' } });
  }
  assert.equal((await host.getState()).folderLabel, 'chosen');
  await rename(target, join(root, 'old'));
  await mkdir(target);
  const { job } = await host.startScan({ toolIds: ['osv'], aiConsent: false });
  let current;
  do {
    current = (await host.getJob()).job;
    if (current.state === 'running') await new Promise((resolve) => setImmediate(resolve));
  } while (current.state === 'running');
  assert.equal(current.id, job.id);
  assert.equal(current.errorCode, 'execution_path_changed');
});

test('AI jobs require consent from the renderer and the native confirmation, and setup URLs are fixed', async (t) => {
  const opened = [];
  let nativePrompts = 0;
  const { host, scans } = await fixture(t, { confirmAI: async () => { nativePrompts++; return false; }, openExternal: async (url) => opened.push(url) });
  await host.chooseFolder();
  assert.deepEqual(await host.startScan({ toolIds: ['open-code-review'], aiConsent: false }), { error: { code: 'ai_consent_required' } });
  assert.equal(nativePrompts, 0);
  assert.deepEqual(await host.startScan({ toolIds: ['open-code-review'], aiConsent: true }), { error: { code: 'ai_consent_required' } });
  assert.equal(nativePrompts, 1);
  assert.equal(scans.length, 0);
  assert.deepEqual(await host.openSetup('open-code-review', 'https://example.invalid'), { error: { code: 'setup_unavailable' } });
  assert.deepEqual(await host.openSetup('open-code-review', 'sign_in'), { ok: true });
  assert.deepEqual(opened, ['https://github.com/alibaba/open-code-review']);
});

test('desktop report IDs resolve on the same origin only inside the authorized desktop session', async (t) => {
  const { runs } = await fixture(t);
  const privateRun = JSON.parse(await readFile(new URL('run.json', sample), 'utf8'));
  privateRun.id = 'desktop-example';
  await writeFile(join(runs, 'run.json'), JSON.stringify(privateRun));
  const server = await startDashboard({ runs: samplePath, desktopCatalog: { runs, token } });
  t.after(() => server.close());
  const privateHeaders = { 'x-sec-hub-desktop': token };
  const updated = await server.refreshDesktopCatalog([{ id: 'job', resultRunId: 'desktop-example', reportsReady: true }]);
  assert.equal(updated.catalog.artifacts.length, 1);
  const detail = new URL(`api/artifacts/${updated.results[0].artifactId}`, server.url);
  const authorized = await (await fetch(detail, { headers: privateHeaders })).json();
  assert.equal(authorized.run.id, 'desktop-example');
  assert.equal((await fetch(detail)).status, 404);
  assert.equal((await fetch(detail, { headers: { 'x-sec-hub-desktop': 'b'.repeat(64) } })).status, 404);
  const privateCatalog = await (await fetch(new URL('api/catalog', server.url), { headers: privateHeaders })).json();
  assert.equal(privateCatalog.snapshot.refresh, 'explicit');
  assert.equal((await fetch(new URL('api/execution', server.url), { headers: privateHeaders })).status, 404);
  const publicCatalog = await (await fetch(new URL('api/catalog', server.url))).json();
  assert.equal(publicCatalog.snapshot.refresh, 'restart');
});

test('the desktop job disables Git and cancellation remains active until the scanner is joined', async (t) => {
  let input;
  let enter;
  let finish;
  const started = new Promise((resolve) => { enter = resolve; });
  const finishing = new Promise((resolve) => { finish = resolve; });
  const { host } = await fixture(t, {
    scan: async (value) => {
      input = value;
      enter();
      await finishing;
      return { id: 'cancelled-test', status: 'failed', directory: value.out };
    },
  });
  try {
    await host.chooseFolder();
    const request = { toolIds: ['osv'], aiConsent: false };
    const { job } = await host.startScan(request);
    await started;
    assert.equal(input.inspectGit, false);
    assert.equal(input.ai, false);
    const cancelled = host.cancelScan();
    assert.equal(cancelled.job.id, job.id);
    assert.equal(cancelled.job.state, 'cancelling');
    assert.equal(input.signal.aborted, true);
    assert.deepEqual(await host.startScan(request), { error: { code: 'execution_busy' } });
  } finally { finish(); await host.close(); }
  assert.equal(host.getJob().job.state, 'cancelled');
});

test('desktop scans never execute a repository-controlled Git clean filter', async (t) => {
  try { execFileSync('git', ['--version'], { stdio: 'ignore' }); }
  catch { return t.skip('Git is required for this fixture'); }
  const { target, runs } = await fixture(t);
  const git = (...args) => execFileSync('git', args, { cwd: target, stdio: 'ignore' });
  git('init', '-q');
  await writeFile(join(target, 'tracked'), 'original\n');
  git('add', 'tracked');
  git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false', 'commit', '-qm', 'fixture');
  await writeFile(join(target, '.gitattributes'), 'tracked filter=fixture\n');
  git('config', 'filter.fixture.clean', 'echo invoked > filter-marker; cat');
  await writeFile(join(target, 'tracked'), 'modified\n');
  const older = new Date(Date.now() - 60_000);
  await utimes(join(target, 'tracked'), older, older);

  const marker = join(target, 'filter-marker');
  await runScan({ target, out: join(runs, 'desktop'), tools: [], inspectGit: false });
  await assert.rejects(access(marker), { code: 'ENOENT' });

  await runScan({ target, out: join(runs, 'cli'), tools: [] });
  assert.match(await readFile(marker, 'utf8'), /invoked/);
});

test('IPC sender validation rejects foreign contents, sessions, origins and subframes', () => {
  const activeUrl = 'http://127.0.0.1:41415/';
  const session = {};
  const frame = { url: activeUrl };
  const contents = { mainFrame: frame, session, isDestroyed: () => false };
  const valid = { sender: contents, senderFrame: frame };
  assert.equal(isTrustedSender(valid, contents, session, activeUrl), true);
  assert.equal(isTrustedSender({ ...valid, sender: { ...contents } }, contents, session, activeUrl), false);
  assert.equal(isTrustedSender(valid, contents, {}, activeUrl), false);
  assert.equal(isTrustedSender({ ...valid, senderFrame: { url: activeUrl } }, contents, session, activeUrl), false);
  frame.url = 'http://127.0.0.1:31415/';
  assert.equal(isTrustedSender(valid, contents, session, activeUrl), false);
});
