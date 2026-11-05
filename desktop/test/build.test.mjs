import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const build = await import('../build.mjs').catch(() => ({}));
const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
async function fixture(t) {
  const dir = await mkdtemp(path.join(tmpdir(), 'sec-hub-build-test-'));
  t.after(() => rm(dir, { recursive: true, force: true }));
  return dir;
}
async function file(root, name, body = name) {
  const p = path.join(root, name); await mkdir(path.dirname(p), { recursive: true }); await writeFile(p, body);
}

test('a cached archive with the wrong digest is rejected before extraction', async t => {
  assert.equal(typeof build.verifyArchive, 'function', 'archive verification is required');
  const dir = await fixture(t); const archive = path.join(dir, 'runtime.zip'); await writeFile(archive, 'modified');
  await assert.rejects(build.verifyArchive(archive, { sha256: '0'.repeat(64), size: 8 }), /SHA-256/i);
  const actual = createHash('sha256').update('modified').digest('hex');
  await assert.rejects(build.verifyArchive(archive, { sha256: actual, size: 99 }), /size/i);
});

test('packaging requires absolute output and cache paths outside the real source tree', async t => {
  assert.equal(typeof build.validatePaths, 'function', 'path confinement is required');
  const dir = await fixture(t);
  await assert.rejects(build.validatePaths({ repository, out: 'relative', cache: dir }), /absolute/i);
  await assert.rejects(build.validatePaths({ repository, out: path.join(repository, 'dist'), cache: dir }), /outside/i);
  await assert.rejects(build.validatePaths({ repository, out: dir, cache: repository }), /outside/i);
  if (process.platform !== 'win32') {
    await symlink(repository, path.join(dir, 'repo-link'));
    await assert.rejects(build.validatePaths({ repository, out: path.join(dir, 'repo-link', 'dist'), cache: dir }), /outside/i);
  }
});

test('staging includes only app entrypoints, synthetic JSON and the explicit core payload', async t => {
  assert.equal(typeof build.stagePayload, 'function', 'allowlisted staging is required');
  const dir = await fixture(t); const repo = path.join(dir, 'repo'); const resources = path.join(dir, 'resources');
  for (const name of ['desktop/app/main.cjs', 'desktop/app/controller.mjs', 'desktop/app/policy.mjs', 'desktop/app/smoke.mjs', 'desktop/app/package.json', 'desktop/app/sample/run.json', 'src/dashboard/server.mjs', 'package.json']) await file(repo, name, name.endsWith('package.json') ? '{"version":"0.1.0"}' : name);
  for (const name of ['desktop/app/test/private.json', 'desktop/app/sample/secret.txt', 'desktop/app/dev-scratch.mjs', 'verification/private.json', 'results/private.json', '.env', 'bin/sec-hub.mjs', 'examples/private.json']) await file(repo, name, 'PRIVATE');
  const payload = await build.stagePayload({ repository: repo, resources });
  assert.deepEqual(payload.files.map(f => f.path).sort(), ['app/controller.mjs', 'app/main.cjs', 'app/package.json', 'app/policy.mjs', 'app/sample/run.json', 'app/smoke.mjs', 'core/package.json', 'core/src/dashboard/server.mjs']);
  assert.equal(await readFile(path.join(resources, 'core/src/dashboard/server.mjs'), 'utf8'), 'src/dashboard/server.mjs');
  assert.deepEqual((await readdir(resources)).sort(), ['app', 'core']);
});

test('staging rejects symbolic source files rather than copying private targets', async t => {
  assert.equal(typeof build.stagePayload, 'function', 'safe staging is required');
  if (process.platform === 'win32') return t.skip('symlink privilege is not assumed on Windows');
  const dir = await fixture(t); const repo = path.join(dir, 'repo');
  await file(repo, 'desktop/app/package.json', '{}'); await file(repo, 'desktop/app/main.cjs'); await file(repo, 'package.json', '{}');
  await mkdir(path.join(repo, 'src')); await file(dir, 'private', 'SECRET'); await symlink(path.join(dir, 'private'), path.join(repo, 'src/leak.mjs'));
  await assert.rejects(build.stagePayload({ repository: repo, resources: path.join(dir, 'resources') }), /symbolic/i);
});

test('runtime validation requires both vendor notices and the executable', async t => {
  assert.equal(typeof build.validateRuntime, 'function', 'complete runtime validation is required');
  const dir = await fixture(t);
  await file(dir, 'electron.exe'); await file(dir, 'LICENSE');
  await assert.rejects(build.validateRuntime(dir, 'win32-x64'), /LICENSES.chromium.html/);
  await file(dir, 'LICENSES.chromium.html'); await build.validateRuntime(dir, 'win32-x64');
  await rm(path.join(dir, 'electron.exe'));
  await assert.rejects(build.validateRuntime(dir, 'win32-x64'), /electron.exe/);
});

test('platform layout returns the actual named executable and resources directory', () => {
  assert.equal(typeof build.platformLayout, 'function', 'native platform layout is required');
  const base = path.resolve('/package');
  assert.deepEqual(build.platformLayout(base, 'darwin-arm64'), { application: path.join(base, 'Sec Hub.app'), executable: path.join(base, 'Sec Hub.app/Contents/MacOS/SecHub'), resources: path.join(base, 'Sec Hub.app/Contents/Resources') });
  assert.deepEqual(build.platformLayout(base, 'win32-x64'), { application: path.join(base, 'Sec Hub'), executable: path.join(base, 'Sec Hub/Sec Hub.exe'), resources: path.join(base, 'Sec Hub/resources') });
  assert.throws(() => build.platformLayout(base, 'linux-x64'), /unsupported/i);
});

const smoke = await import('../smoke.mjs').catch(() => ({}));
test('packaged smoke rejects missing renderer evidence and mismatched embedded runtime', () => {
  assert.equal(typeof smoke.validateSummary, 'function', 'runtime smoke validation is required');
  const summary = { status: 'passed', runtime: { electron: '45.1.0', node: '24.22.1', platform: 'darwin', arch: 'arm64' }, checks: { rendererLoad: true, catalog: true, securityPreferences: true, folderSwitch: true, singleInstance: true, closedPort: true, executionUnavailable: true, nativeScan: true }, urls: ['http://127.0.0.1:12345/', 'http://127.0.0.1:12346/'], secondary: { exitCode: 0, signal: null } };
  assert.doesNotThrow(() => smoke.validateSummary(summary, { electron: '45.1.0', node: '24.22.1' }, 'darwin-arm64'));
  assert.throws(() => smoke.validateSummary({ ...summary, checks: { ...summary.checks, rendererLoad: false } }, { electron: '45.1.0', node: '24.22.1' }, 'darwin-arm64'), /rendererLoad/);
  assert.throws(() => smoke.validateSummary({ ...summary, runtime: { ...summary.runtime, node: '22.0.0' } }, { electron: '45.1.0', node: '24.22.1' }, 'darwin-arm64'), /runtime/i);
  assert.throws(() => smoke.validateSummary({ ...summary, urls: ['https://example.com/', 'http://127.0.0.1:12346/'] }, { electron: '45.1.0', node: '24.22.1' }, 'darwin-arm64'), /loopback/i);
});

test('external smoke port probe fails while an owned server still listens', async t => {
  assert.equal(typeof smoke.assertClosedPort, 'function', 'external port verification is required');
  const { createServer } = await import('node:net'); const server = createServer();
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  const url = `http://127.0.0.1:${server.address().port}/`;
  await assert.rejects(smoke.assertClosedPort(url), /still listening/i);
  await new Promise(resolve => server.close(resolve));
  await assert.doesNotReject(smoke.assertClosedPort(url));
});

test('macOS helper rebranding supplies the executable key absent from official helper plists', { skip: process.platform !== 'darwin' }, async t => {
  const dir = await fixture(t); const app = path.join(dir, 'Sec Hub.app');
  const plist = keys => `<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict>${Object.entries(keys).map(([k,v]) => `<key>${k}</key><string>${v}</string>`).join('')}</dict></plist>`;
  await file(app, 'Contents/Info.plist', plist({ CFBundleExecutable: 'Electron', CFBundleIdentifier: 'com.github.Electron', CFBundleName: 'Electron', CFBundleDisplayName: 'Electron', CFBundleShortVersionString: '45.1.0', CFBundleVersion: '45.1.0', ElectronAsarIntegrity: 'removed' }));
  await file(app, 'Contents/MacOS/Electron');
  await file(app, 'Contents/Frameworks/Electron Helper.app/Contents/Info.plist', plist({ CFBundleIdentifier: 'com.github.Electron.helper', CFBundleName: 'Electron Helper' }));
  await file(app, 'Contents/Frameworks/Electron Helper.app/Contents/MacOS/Electron Helper');
  await build.rebrandMac(app, '0.1.0');
  await assert.doesNotReject(readFile(path.join(app, 'Contents/Frameworks/Sec Hub Helper.app/Contents/MacOS/Sec Hub Helper')));
  const { execFileSync } = await import('node:child_process');
  assert.equal(execFileSync('/usr/libexec/PlistBuddy', ['-c', 'Print :CFBundleExecutable', path.join(app, 'Contents/Frameworks/Sec Hub Helper.app/Contents/Info.plist')], { encoding: 'utf8' }).trim(), 'Sec Hub Helper');
});

test('staging rejects an app directory symlink before following its entrypoints', { skip: process.platform === 'win32' }, async t => {
  const dir = await fixture(t); const repo = path.join(dir, 'repo'); const external = path.join(dir, 'external');
  for (const name of ['package.json', 'main.cjs', 'controller.mjs', 'policy.mjs', 'smoke.mjs', 'sample/run.json']) await file(external, name, '{}');
  await mkdir(path.join(repo, 'desktop'), { recursive: true }); await symlink(external, path.join(repo, 'desktop/app'));
  await file(repo, 'package.json', '{}'); await file(repo, 'src/dashboard/server.mjs');
  await assert.rejects(build.stagePayload({ repository: repo, resources: path.join(dir, 'resources') }), /symbolic/i);
});

test('signing preparation removes Finder metadata only from the assembled output', { skip: process.platform !== 'darwin' }, async t => {
  assert.equal(typeof build.prepareMacSigning, 'function', 'normal signing metadata preparation is required');
  const { execFileSync } = await import('node:child_process'); const dir = await fixture(t);
  execFileSync('/usr/bin/xattr', ['-wx', 'com.apple.FinderInfo', '00'.repeat(32), dir]);
  execFileSync('/usr/bin/xattr', ['-w', 'org.sechub.test-preserved', 'preserved', dir]);
  await build.prepareMacSigning(dir);
  const names = execFileSync('/usr/bin/xattr', [dir], { encoding: 'utf8' });
  assert.equal(names.includes('com.apple.FinderInfo'), false);
  assert.equal(execFileSync('/usr/bin/xattr', ['-p', 'org.sechub.test-preserved', dir], { encoding: 'utf8' }).trim(), 'preserved');
});

test('smoke refuses a nonempty evidence directory before validating or launching an executable', async t => {
  const dir = await fixture(t); await file(dir, 'application-stderr.log', 'previous evidence');
  await assert.rejects(smoke.smoke({ executable: path.join(dir, 'missing-executable'), out: dir }), /empty/i);
  assert.equal(await readFile(path.join(dir, 'application-stderr.log'), 'utf8'), 'previous evidence');
});

async function signedMacFixture(t) {
  const { execFileSync } = await import('node:child_process');
  const { copyFile, chmod } = await import('node:fs/promises');
  const dir = await fixture(t); const application = path.join(dir, 'Sec Hub.app');
  await file(application, 'Contents/Info.plist', '<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleExecutable</key><string>Fixture</string><key>CFBundleIdentifier</key><string>org.sechub.archive-fixture</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>');
  await mkdir(path.join(application, 'Contents/MacOS'), { recursive: true });
  await copyFile('/usr/bin/true', path.join(application, 'Contents/MacOS/Fixture')); await chmod(path.join(application, 'Contents/MacOS/Fixture'), 0o755);
  await file(application, 'Contents/Resources/preserved.txt', 'fixture metadata');
  execFileSync('/usr/bin/xattr', ['-w', 'org.sechub.test-preserved', 'preserved', path.join(application, 'Contents/Resources/preserved.txt')]);
  execFileSync('/usr/bin/xattr', ['-w', 'com.apple.quarantine', '0081;6ae30000;SecHubMetadataFixture;', path.join(application, 'Contents/Resources/preserved.txt')]);
  execFileSync('/usr/bin/codesign', ['--force', '--sign', '-', application], { stdio: 'pipe' });
  return { dir, application };
}
async function fixtureInventory(root, prefix = '') {
  const { lstat } = await import('node:fs/promises'); const files = [];
  for (const name of (await readdir(path.join(root, prefix))).sort()) {
    const relative = path.join(prefix, name); const info = await lstat(path.join(root, relative));
    if (info.isDirectory()) files.push(...await fixtureInventory(root, relative));
    else files.push({ path: relative.split(path.sep).join('/'), type: 'file', size: info.size, mode: (info.mode & 0o777).toString(8), sha256: createHash('sha256').update(await readFile(path.join(root, relative))).digest('hex') });
  }
  return files;
}

test('the actual packing and fresh extraction gate preserves quarantine and unrelated metadata', { skip: process.platform !== 'darwin' }, async t => {
  assert.equal(typeof build.packAndVerify, 'function', 'the distributable archive must be roundtrip verified');
  const { execFileSync } = await import('node:child_process');
  const { dir, application } = await signedMacFixture(t); const expectedFiles = await fixtureInventory(application);
  const previous = process.env.DITTONORSRC; process.env.DITTONORSRC = '1';
  let result;
  try { result = await build.packAndVerify({ application, archive: path.join(dir, 'fixture.zip'), target: 'darwin-arm64', expectedFiles }); }
  finally { if (previous === undefined) delete process.env.DITTONORSRC; else process.env.DITTONORSRC = previous; }
  t.after(() => rm(result.directory, { recursive: true, force: true }));
  assert.deepEqual(result.files, expectedFiles);
  assert.equal(result.verification.macStrictSignature, true);
  const preserved = path.join(result.application, 'Contents/Resources/preserved.txt');
  assert.equal(execFileSync('/usr/bin/xattr', ['-p', 'org.sechub.test-preserved', preserved], { encoding: 'utf8' }).trim(), 'preserved');
  assert.match(execFileSync('/usr/bin/xattr', ['-p', 'com.apple.quarantine', preserved], { encoding: 'utf8' }).trim(), /^0081;/);
  assert.equal(execFileSync('/usr/bin/xattr', [result.application], { encoding: 'utf8' }).includes('com.apple.FinderInfo'), false);
});

test('the distributable gate rejects an archive whose extracted bytes differ from the signed inventory', { skip: process.platform !== 'darwin' }, async t => {
  assert.equal(typeof build.packAndVerify, 'function', 'roundtrip inventory comparison is required');
  const { dir, application } = await signedMacFixture(t); const expectedFiles = await fixtureInventory(application); expectedFiles[0].sha256 = '0'.repeat(64);
  await assert.rejects(build.packAndVerify({ application, archive: path.join(dir, 'fixture.zip'), target: 'darwin-arm64', expectedFiles }), /inventory/i);
});

test('the distributable gate rejects invalid attached Finder metadata after extraction without repairing it', { skip: process.platform !== 'darwin' }, async t => {
  assert.equal(typeof build.packAndVerify, 'function', 'post-extraction signature verification is required');
  const { execFileSync } = await import('node:child_process'); const { dir, application } = await signedMacFixture(t);
  execFileSync('/usr/bin/xattr', ['-wx', 'com.apple.FinderInfo', '0000000000000000200000000000000000000000000000000000000000000000', path.join(application, 'Contents/Resources/preserved.txt')]);
  await assert.rejects(build.packAndVerify({ application, archive: path.join(dir, 'fixture.zip'), target: 'darwin-arm64', expectedFiles: await fixtureInventory(application) }), /codesign|Finder|attached/i);
});
