import test from 'node:test';
import { execFileSync } from 'node:child_process';
import assert from 'node:assert/strict';
import { access, chmod, mkdtemp, mkdir, readFile, realpath, rename, rm, utimes, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../src/runner.mjs';
import { startDashboard } from '../../src/dashboard/server.mjs';
import { createDesktopScanController } from '../../src/dashboard/desktop-execution.mjs';
import { inspectDesktopTooling } from '../../src/dashboard/desktop-tooling.mjs';
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

test('one native config selection passes all seven adapters and the explicit endpoint to one job', async (t) => {
  let chosen;
  let received;
  const started = new Promise((resolve) => { received = resolve; });
  let consent;
  const { host, root, target } = await fixture(t, {
    pickConfig: async () => chosen,
    pickNode: async () => process.execPath,
    inspectTools: async ({ config } = {}) => Object.entries(config?.tools ?? {}).map(([id, tool]) => ({
      id, ...tool, installation: 'installed',
      ai: ['codex-security', 'open-code-review', 'cloudflare', 'anthropic'].includes(id),
      ...(id === 'cloudflare' ? { nodeExecutable: process.execPath } : {}),
    })),
    confirmAI: async ({ toolIds }) => { consent = toolIds; return true; },
    scan: async (value) => { received(value); return { id: 'seven', status: 'completed', directory: value.out }; },
  });
  const toolIds = ['osv', 'skillspector', 'codex-security', 'open-code-review', 'php2shell', 'cloudflare', 'anthropic'];
  const workRoot = join(root, 'work');
  const tools = Object.fromEntries(toolIds.map(id => [id, { command: process.execPath, args: [] }]));
  tools['codex-security'].scanOptions = { auth: 'chatgpt' };
  tools.cloudflare.agentOptions = { model: 'local-test-model', workRoot, skillRoot: root, revision: 'c'.repeat(40) };
  tools.anthropic.agentOptions = { model: 'local-test-model', workRoot, skillRoot: root, revision: 'd'.repeat(40) };
  chosen = join(root, 'trusted.json');
  await writeFile(chosen, JSON.stringify({ tools }));
  await host.chooseFolder();
  const configured = await host.chooseConfig();
  assert.equal(configured.configLabel, 'trusted.json');
  assert.equal(configured.tools.filter(tool => tool.selectable).length, 7);
  for (const secret of [root, target, process.execPath, 'local-test-model']) assert.ok(!JSON.stringify(configured).includes(secret));
  assert.equal((await host.chooseNode()).nodeConfigured, true);

  const request = { toolIds, aiConsent: true };
  assert.deepEqual(await host.startScan(request), { error: { code: 'php_url_required' } });
  for (const phpUrl of ['ftp://127.0.0.1/', 'https://user:secret@127.0.0.1/', 'https:/127.0.0.1', 'https://127.0.0.1/\nfoo', 'https://127.0.0.1/?secret=x', 'https://127.0.0.1/#fragment']) {
    assert.deepEqual(await host.startScan({ ...request, phpUrl }), { error: { code: 'invalid_php_url' } });
  }
  const phpUrl = 'http://127.0.0.1:8080/';
  const { job } = await host.startScan({ ...request, phpUrl });
  assert.deepEqual(job.toolIds, toolIds);
  const input = await started;
  assert.deepEqual(consent, ['codex-security', 'open-code-review', 'cloudflare', 'anthropic']);
  assert.equal(input.target, target);
  assert.equal(input.url, phpUrl);
  assert.equal(input.nodeExecutable, process.execPath);
  assert.deepEqual(input.config.tools['codex-security'].scanOptions, { auth: 'chatgpt' });
  assert.equal(input.config.tools.cloudflare.agentOptions.workRoot, workRoot);
  assert.equal(input.config.tools.anthropic.agentOptions.model, 'local-test-model');
});

test('unsafe, oversized and unknown config files preserve the last trusted snapshot', async (t) => {
  let chosen;
  const { host, root, target } = await fixture(t, { pickConfig: async () => chosen });
  await host.chooseFolder();
  chosen = join(root, 'good.json');
  await writeFile(chosen, '{"tools":{}}');
  assert.equal((await host.chooseConfig()).configLabel, 'good.json');
  for (const [filename, contents] of [
    [join(target, 'in-project.json'), '{"tools":{}}'],
    [join(root, 'big.json'), ' '.repeat(256 * 1024 + 1)],
    [join(root, 'unknown.json'), '{"tools":{"arbitrary":{"command":"node"}}}'],
  ]) {
    chosen = filename;
    await writeFile(chosen, contents);
    assert.deepEqual(await host.chooseConfig(), { error: { code: 'config_unavailable' } });
    assert.equal((await host.getState()).configLabel, 'good.json');
  }
  assert.deepEqual(await host.startScan({ toolIds: ['arbitrary'], aiConsent: true }), { error: { code: 'invalid_request' } });
});

test('the desktop inspector and real engine publish one result for two offline executable fixtures', async (t) => {
  let chosen;
  let resolveReports;
  const reported = new Promise(resolve => { resolveReports = resolve; });
  const baseTools = ['osv', 'php2shell'].map(id => ({ id, installation: 'missing', ai: false }));
  const { host, root, runs, target } = await fixture(t, {
    pickConfig: async () => chosen,
    inspectTools: async settings => inspectDesktopTooling(baseTools, settings),
    scan: runScan,
    report: async run => resolveReports(run),
  });
  const phpUrl = 'http://127.0.0.1:1/explicit';
  const checker = join(root, 'phpcheck.js');
  const osv = join(root, 'osv.cjs');
  await writeFile(checker, `
    if (process.argv[2] === '--version') console.log('fixture 1.0');
    else if (process.argv[2] === ${JSON.stringify(phpUrl)} && process.argv[3] === '--json') {
      console.log(JSON.stringify({ patch_status: 'unknown', reason: 'Fixture header unavailable', php_version: null, exit_code: 3 }));
      process.exitCode = 3;
    } else process.exitCode = 2;
  `);
  await writeFile(osv, `
    if (process.argv[2] === '--version') console.log('fixture 1.0');
    else require('node:fs').writeFileSync(process.argv[process.argv.indexOf('--output-file') + 1], '{"results":[]}');
  `);
  chosen = join(root, 'tools.json');
  await writeFile(chosen, JSON.stringify({ tools: {
    osv: { command: process.execPath, args: [osv] },
    php2shell: { command: process.execPath, args: [checker] },
  } }));
  await host.chooseFolder();
  assert.equal((await host.chooseConfig()).tools.filter(tool => tool.selectable).length, 2);
  // The original reviewed snapshot remains the authority for this session.
  await writeFile(chosen, '{"tools":{}}');
  const { job } = await host.startScan({ toolIds: ['osv', 'php2shell'], aiConsent: false, phpUrl });
  assert.ok(job);
  const run = await Promise.race([reported, new Promise((_, reject) => {
    const timer = setTimeout(() => reject(new Error('No desktop report produced')), 10_000);
    timer.unref();
  })]);
  assert.equal(run.status, 'completed');
  assert.equal(run.directory, join(runs, job.id));
  assert.equal(run.target.path, target);
  assert.deepEqual(run.tools.filter(tool => tool.selected).map(tool => [tool.id, tool.status]), [['osv', 'completed'], ['php2shell', 'completed']]);
  assert.equal(run.findings[0].location.url, phpUrl);
});

test('the desktop inspector blocks project executables and Windows native agent policies', async (t) => {
  const { root, target } = await fixture(t);
  const projectScanner = join(target, process.platform === 'win32' ? 'skillspector.exe' : 'skillspector');
  await writeFile(projectScanner, 'fixture');
  await chmod(projectScanner, 0o700);
  const baseTools = ['skillspector', 'cloudflare', 'anthropic'].map(id => ({ id, installation: 'unknown' }));
  const config = { tools: { skillspector: { command: projectScanner } } };
  const settings = { targetPath: target, config, configPath: join(root, 'tools.json') };
  const actual = await inspectDesktopTooling(baseTools, settings);
  assert.equal(actual[0].command, undefined);
  assert.equal(actual[0].unavailableReason, 'executable_missing');
  const windows = await inspectDesktopTooling(baseTools, { ...settings, platform: 'win32' });
  for (const tool of windows.slice(1)) {
    assert.equal(tool.command, undefined);
    assert.equal(tool.unavailableReason, 'platform_unsupported');
  }
});

test('desktop report IDs resolve on the same origin only inside the authorized desktop session', async (t) => {
  const { runs } = await fixture(t);
  const privateRun = JSON.parse(await readFile(new URL('run.json', sample), 'utf8'));
  privateRun.id = 'desktop-example';
  privateRun.target.path = 'C:\\Users\\Developer\\repo';
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
