import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import { atomicWriteFile } from '../src/safe-io.mjs';

const helper = fileURLToPath(new URL('../src/native/darwin-acl-reader', import.meta.url));
const supported = process.platform === 'darwin' && ['arm64', 'x64'].includes(process.arch);
async function fixture(t) {
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), 'sec-hub-native-acl-')));
  t.after(async () => { childProcess.spawnSync('/bin/chmod', ['-RN', root]); await fs.rm(root, { recursive: true, force: true }); });
  return root;
}
function runHelper(fd) {
  return childProcess.spawnSync(helper, [], {
    stdio: ['ignore', 'pipe', 'pipe', ...(fd === undefined ? [] : [fd])],
    encoding: 'utf8', timeout: 5000, env: {},
  });
}

// A zero exit without the exact native attestation must never authorize writes.
for (const [label, code] of [
  ['malformed success', "process.stdout.write('not an ACL result\\n')"],
  ['empty success', ''],
  ['native query error', "process.stderr.write('ACL query failed: EIO');process.exitCode=2"],
  ['contradictory stderr', "process.stdout.write('SEC_HUB_ACL_OK\\n');process.stderr.write('ACL query failed')"],
  ['output overflow', "process.stdout.write('x'.repeat(128*1024))"],
]) {
  test(`native ACL ${label} rejects before file mutation`, { skip: !supported }, async t => {
    const root = await fixture(t), spawn = childProcess.spawn;
    childProcess.spawn = (command, args, options) => command === helper
      ? spawn(process.execPath, ['-e', code], options)
      : spawn(command, args, options);
    syncBuiltinESMExports();
    try {
      await assert.rejects(atomicWriteFile(join(root, 'report'), 'secret'), /ACL/i);
      assert.deepEqual(await fs.readdir(root), []);
    } finally { childProcess.spawn = spawn; syncBuiltinESMExports(); }
  });
}

test('native ACL helper timeout bounds a stuck reader and prevents mutation', { skip: !supported }, async t => {
  const root = await fixture(t), spawn = childProcess.spawn;
  childProcess.spawn = (command, args, options) => command === helper
    ? spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], options)
    : spawn(command, args, options);
  syncBuiltinESMExports();
  const started = performance.now();
  try {
    await assert.rejects(atomicWriteFile(join(root, 'report'), 'secret'), /ACL.*timed out/i);
    assert.ok(performance.now() - started < 8000);
    assert.deepEqual(await fs.readdir(root), []);
  } finally { childProcess.spawn = spawn; syncBuiltinESMExports(); }
});

test('missing bundled native ACL helper fails closed without compiling', { skip: !supported }, async t => {
  const root = await fixture(t), isolated = join(root, 'safe-io.mjs');
  await fs.copyFile(new URL('../src/safe-io.mjs', import.meta.url), isolated);
  const safe = await import(pathToFileURL(isolated).href);
  await assert.rejects(safe.atomicWriteFile(join(root, 'report'), 'secret'), /ACL/i);
  assert.deepEqual(await fs.readdir(root), ['safe-io.mjs']);
});

test('unsupported macOS architecture fails before output mutation (modeled architecture)', { skip: !supported }, async t => {
  const root = await fixture(t), descriptor = Object.getOwnPropertyDescriptor(process, 'arch');
  Object.defineProperty(process, 'arch', { value: 'unsupported-arch' });
  try {
    await assert.rejects(atomicWriteFile(join(root, 'report'), 'secret'), /architecture|ACL/i);
    assert.deepEqual(await fs.readdir(root), []);
  } finally { Object.defineProperty(process, 'arch', descriptor); }
});

test('native ACL helper requires an inherited directory fd', { skip: !supported }, async t => {
  const missing = runHelper();
  assert.ok(Number.isInteger(missing.status) && missing.status !== 0, missing.error?.message);
  assert.equal(missing.stdout, '');
  const root = await fixture(t), file = join(root, 'file');
  await fs.writeFile(file, 'data');
  const handle = await fs.open(file, 'r');
  try {
    const regular = runHelper(handle.fd);
    assert.ok(Number.isInteger(regular.status) && regular.status !== 0, regular.error?.message);
    assert.equal(regular.stdout, '');
  } finally { await handle.close(); }
});

test('native ACL helper reads empty, deny, allow and unreadable ACLs on the actual fd', { skip: !supported }, async t => {
  const root = await fixture(t), handle = await fs.open(root, 'r');
  try {
    let result = runHelper(handle.fd);
    assert.equal(result.status, 0, result.error?.message || result.stderr);
    assert.equal(result.stdout, 'SEC_HUB_ACL_OK\n');
    for (const [acl, accepted] of [
      ['everyone deny delete', true],
      ['everyone allow add_file', false],
      ['everyone deny readsecurity', false],
    ]) {
      const changed = childProcess.spawnSync('/bin/chmod', ['+a', acl, root], { encoding: 'utf8' });
      assert.equal(changed.status, 0, changed.stderr);
      result = runHelper(handle.fd);
      assert.equal(result.status === 0, accepted, `${acl}: ${result.stderr}`);
      assert.equal(result.stdout, accepted ? 'SEC_HUB_ACL_OK\n' : '');
    }
  } finally { await handle.close(); }
});

test('native ACL helper stays attached to the opened directory after pathname replacement', { skip: !supported }, async t => {
  const root = await fixture(t), directory = join(root, 'opened');
  await fs.mkdir(directory);
  const handle = await fs.open(directory, 'r');
  try {
    await fs.rename(directory, join(root, 'parked'));
    await fs.mkdir(directory);
    const changed = childProcess.spawnSync('/bin/chmod', ['+a', 'everyone allow add_file', directory], { encoding: 'utf8' });
    assert.equal(changed.status, 0, changed.stderr);
    const result = runHelper(handle.fd);
    assert.equal(result.status, 0, result.error?.message || result.stderr);
    assert.equal(result.stdout, 'SEC_HUB_ACL_OK\n');
  } finally { await handle.close(); }
});
