import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

async function main() {
  if (!['linux', 'darwin'].includes(process.platform)) throw new Error('Fresh package smoke supports POSIX only; Windows safe I/O is unsupported');
  if (!process.env.CI_ARTIFACT_DIR || !isAbsolute(process.env.CI_ARTIFACT_DIR)) throw new Error('CI_ARTIFACT_DIR must be an absolute evidence directory');
  const output = join(resolve(process.env.CI_ARTIFACT_DIR), 'package');
  await mkdir(output, { recursive: true, mode: 0o700 });
  const temporary = await realpath(await mkdtemp(join(tmpdir(), 'sec-hub-package-ci-')));
  const env = { ...process.env, TMPDIR: temporary, TMP: temporary, TEMP: temporary };
  const summary = {
    kind: 'ephemeral-current-source-ci-candidate', platform: process.platform,
    architecture: process.arch, node: process.version,
    sourceCommit: execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim(),
    startedAt: new Date().toISOString(), syntheticExecution: true,
    providerExecution: false, commands: [],
  };
  let server, serverClosed;
  const command = async (label, executable, args, { cwd = temporary, expected = 0 } = {}) => {
    let stdout = '', stderr = '', error;
    const child = spawn(executable, args, { cwd, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    child.stdout.on('data', chunk => { stdout += chunk; });
    child.stderr.on('data', chunk => { stderr += chunk; });
    child.once('error', cause => { error = cause.message; });
    const deadline = setTimeout(() => child.kill('SIGKILL'), 90_000);
    const status = await new Promise(resolveClose => child.once('close', code => resolveClose(code)));
    clearTimeout(deadline);
    await writeFile(join(output, `${label}.stdout.log`), stdout);
    await writeFile(join(output, `${label}.stderr.log`), stderr);
    summary.commands.push({ label, executable, args, status, expected, ...(error ? { error } : {}) });
    assert.equal(status, expected, `${label}: ${error ?? stderr ?? stdout}`);
    return stdout;
  };
  try {
    const metadata = JSON.parse(await readFile(join(root, 'package.json'), 'utf8'));
    summary.version = metadata.version;
    const packDirectory = join(temporary, 'pack'), unpacked = join(temporary, 'unpacked'), prefix = join(temporary, 'install');
    for (const directory of [packDirectory, unpacked, prefix]) await mkdir(directory, { mode: 0o700 });
    const [packed] = JSON.parse(await command('npm-pack', 'npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', packDirectory], { cwd: root }));
    assert.equal(packed.name, metadata.name);
    assert.equal(packed.version, metadata.version);
    assert.equal(packed.filename, `${metadata.name}-${metadata.version}.tgz`);
    const archive = join(packDirectory, packed.filename);
    const names = (await command('archive-list', 'tar', ['-tzf', archive])).trim().split('\n');
    assert.ok(names.length > 0);
    for (const name of names) assert.ok(name.startsWith('package/') && !name.split('/').includes('..') && !name.includes('\\'), `Unexpected archive member: ${name}`);
    await command('archive-extract', 'tar', ['-xzf', archive, '-C', unpacked]);
    await writeFile(join(prefix, 'package.json'), JSON.stringify({ name: 'sec-hub-ci-smoke', private: true }) + '\n');
    await command('npm-install', 'npm', ['--prefix', prefix, 'install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', archive]);
    const installed = join(prefix, 'node_modules', metadata.name), extracted = join(unpacked, 'package');
    const payload = [];
    for (const file of packed.files) {
      assert.ok(!isAbsolute(file.path) && !file.path.split('/').includes('..'));
      assert.ok(file.path === 'package.json' || file.path === 'README.md' || /^(bin|src|examples)\//.test(file.path), `Unexpected package payload: ${file.path}`);
      const [source, tar, install] = await Promise.all([root, extracted, installed].map(async directory => {
        const path = join(directory, file.path), info = await lstat(path);
        assert.ok(info.isFile() && !info.isSymbolicLink(), `Payload is not a regular file: ${path}`);
        return { sha256: sha256(await readFile(path)), mode: info.mode & 0o777, size: info.size };
      }));
      assert.deepEqual(tar, source, `Archive payload differs from current source: ${file.path}`);
      assert.deepEqual(install, source, `Installed payload differs from current source: ${file.path}`);
      assert.equal(file.mode, source.mode);
      payload.push({ path: file.path, ...source });
    }
    async function regularFiles(directory, prefix = '') {
      const files = [];
      for (const entry of await readdir(directory, { withFileTypes: true })) {
        const name = prefix + entry.name;
        if (entry.isDirectory()) files.push(...await regularFiles(join(directory, entry.name), `${name}/`));
        else { assert.ok(entry.isFile(), `Unexpected installed/archive member: ${name}`); files.push(name); }
      }
      return files.sort();
    }
    const expectedFiles = packed.files.map(file => file.path).sort();
    assert.deepEqual(await regularFiles(extracted), expectedFiles);
    assert.deepEqual(await regularFiles(installed), expectedFiles);
    await writeFile(join(output, 'payload-equality.json'), JSON.stringify(payload, null, 2) + '\n');
    const executable = join(prefix, 'node_modules', '.bin', 'sec-hub');
    assert.equal(await realpath(executable), join(installed, 'bin', 'sec-hub.mjs'));
    assert.equal((await command('installed-version', executable, ['--version'])).trim(), metadata.version);
    assert.match(await command('installed-help', executable, ['--help']), /Sec Hub.*\n[\s\S]*Usage:/);

    const target = join(temporary, 'synthetic-target'), runs = join(temporary, 'runs'), runDirectory = join(runs, 'synthetic');
    await mkdir(target, { mode: 0o700 });
    await mkdir(runs, { mode: 0o700 });
    await writeFile(join(target, 'package.json'), '{"name":"synthetic-ci-target","version":"1.0.0"}\n');
    const fakeScanner = join(temporary, 'synthetic-osv.mjs'), config = join(temporary, 'synthetic-config.json');
    const fixture = JSON.parse(await readFile(join(root, 'test/fixtures/adapters/osv-positive.json'), 'utf8'));
    fixture.results[0].source.path = join(target, 'package-lock.json');
    await writeFile(fakeScanner, `import { writeFileSync } from 'node:fs';
      if (process.argv.includes('--version')) console.log('synthetic-ci-osv 1.0');
      else { const index = process.argv.indexOf('--output-file'); if (index < 0) throw new Error('Missing output'); writeFileSync(process.argv[index + 1], ${JSON.stringify(JSON.stringify(fixture))}); process.exitCode = 1; }\n`);
    await writeFile(config, JSON.stringify({ tools: { osv: { command: process.execPath, args: [fakeScanner] } } }));
    await command('synthetic-scan', executable, ['scan', target, '--tools', 'osv', '--config', config, '--out', runDirectory], { expected: 1 });
    const run = JSON.parse(await readFile(join(runDirectory, 'run.json'), 'utf8'));
    assert.equal(run.status, 'completed');
    assert.equal(run.tools.find(tool => tool.id === 'osv').status, 'completed');
    assert.equal(run.findings.length, 1);
    const reportsBefore = new Map();
    for (const name of ['run.json', 'report.html', 'results.sarif']) reportsBefore.set(name, await readFile(join(runDirectory, name)));
    await command('synthetic-report', executable, ['report', runDirectory], { expected: 1 });
    for (const [name, bytes] of reportsBefore) assert.deepEqual(await readFile(join(runDirectory, name)), bytes, `Report regeneration changed ${name}`);
    assert.equal(JSON.parse(reportsBefore.get('results.sarif')).version, '2.1.0');
    assert.match(reportsBefore.get('report.html').toString(), /Example vulnerable dependency/);

    let serverOutput = '', serverError = '';
    server = spawn(executable, ['serve', '--runs', runs, '--port', '0'], { cwd: temporary, env, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
    serverClosed = new Promise(resolveClose => server.once('close', code => resolveClose(code)));
    server.stdout.on('data', chunk => { serverOutput += chunk; });
    server.stderr.on('data', chunk => { serverError += chunk; });
    const ready = await new Promise((resolveReady, reject) => {
      const deadline = setTimeout(() => { cleanup(); reject(new Error('Installed dashboard readiness timeout')); }, 15_000);
      const inspect = () => {
        const line = serverOutput.split('\n').find(value => value.startsWith('{'));
        if (line) try { const data = JSON.parse(line); if (data.event === 'listening') { cleanup(); resolveReady(data); } } catch {}
      };
      const earlyClose = () => { cleanup(); reject(new Error(`Installed dashboard exited before ready: ${serverError}`)); };
      const cleanup = () => { clearTimeout(deadline); server.stdout.off('data', inspect); server.off('close', earlyClose); server.off('error', earlyError); };
      const earlyError = error => { cleanup(); reject(error); };
      server.stdout.on('data', inspect); server.once('close', earlyClose); server.once('error', earlyError);
      inspect();
    });
    assert.equal(ready.readOnly, true);
    assert.match(ready.url, /^http:\/\/127\.0\.0\.1:\d+\/$/);
    const request = async (route, options) => fetch(new URL(route, ready.url), { ...options, signal: AbortSignal.timeout(5000) });
    const catalogResponse = await request('/api/catalog');
    assert.equal(catalogResponse.status, 200);
    const catalog = await catalogResponse.json();
    const artifact = catalog.artifacts.find(item => item.kind === 'run' && item.state === 'ready');
    assert.ok(artifact, 'installed read-only API discovers the synthetic run');
    const detailResponse = await request(`/api/artifacts/${artifact.id}`);
    assert.equal(detailResponse.status, 200);
    assert.equal((await detailResponse.json()).run.findings.length, 1);
    assert.equal((await request('/api/catalog', { method: 'POST' })).status, 405);
    const assets = [['/', 'index.html'], ['/assets/app.mjs', 'app.mjs'], ['/assets/style.css', 'style.css'], ['/assets/view-model.mjs', 'view-model.mjs'], ['/assets/i18n.mjs', 'i18n.mjs']];
    for (const [route, name] of assets) {
      const response = await request(route);
      assert.equal(response.status, 200);
      assert.deepEqual(Buffer.from(await response.arrayBuffer()), await readFile(join(installed, 'src/web', name)));
    }
    server.kill('SIGTERM');
    assert.equal(await serverClosed, 0);
    await writeFile(join(output, 'installed-server.stdout.log'), serverOutput);
    await writeFile(join(output, 'installed-server.stderr.log'), serverError);
    for (const file of payload) {
      const path = join(installed, file.path);
      assert.equal(sha256(await readFile(path)), file.sha256, `Smoke mutated installed payload: ${file.path}`);
      assert.equal((await lstat(path)).mode & 0o777, file.mode);
    }
    const candidate = `candidate-${summary.sourceCommit}-${process.platform}-node${process.versions.node.split('.')[0]}.tgz`;
    await copyFile(archive, join(output, candidate));
    summary.candidate = { filename: candidate, sha256: sha256(await readFile(archive)), immutableRelease: false };
    summary.payloadFiles = payload.length;
    summary.checks = ['archive/source/installed byte and mode equality', 'installed executable help/version', 'synthetic scan', 'JSON/HTML/SARIF regeneration', 'installed read-only web API and asset equality', 'installed payload immutability'];
    summary.status = 'passed';
  } catch (error) {
    summary.status = 'failed'; summary.error = error.stack ?? error.message;
    throw error;
  } finally {
    if (server && server.exitCode === null) { server.kill('SIGKILL'); await serverClosed; }
    summary.endedAt = new Date().toISOString();
    await writeFile(join(output, 'summary.json'), JSON.stringify(summary, null, 2) + '\n');
    await rm(temporary, { recursive: true, force: true });
  }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
