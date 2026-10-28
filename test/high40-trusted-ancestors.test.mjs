import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import { syncBuiltinESMExports } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { assertSafeDirectory, ensureSafeDirectory, atomicWriteFile } from '../src/safe-io.mjs';
const execute = promisify(execFile);

async function fixture(t) {
  const root = await fs.realpath(await fs.mkdtemp(join(tmpdir(), 'sec-hub-high40-')));
  t.after(() => fs.rm(root, { recursive: true, force: true }));
  return root;
}

// These tests catch accepting an ancestor that another POSIX user can rename in.
for (const mode of [0o777, 0o770, 0o707]) {
  test(`reject writable ancestor ${mode.toString(8)} before any file or directory creation`, { skip: process.platform === 'win32' }, async t => {
    const root = await fixture(t), shared = join(root, 'shared'), parent = join(shared, 'output');
    await fs.mkdir(parent, { recursive: true });
    await fs.chmod(shared, mode);
    await assert.rejects(assertSafeDirectory(parent), /untrusted.*directory|directory.*untrusted/i);
    await assert.rejects(ensureSafeDirectory(join(parent, 'new')), /untrusted.*directory|directory.*untrusted/i);
    await assert.rejects(atomicWriteFile(join(parent, 'report'), 'secret'), /untrusted.*directory|directory.*untrusted/i);
    assert.deepEqual(await fs.readdir(parent), []);
  });
}

test('reject unsafe requested directory mode before creation', { skip: process.platform === 'win32' }, async t => {
  const root = await fixture(t), output = join(root, 'new');
  await assert.rejects(ensureSafeDirectory(output, { mode: 0o777 }), /mode|untrusted/i);
  assert.deepEqual(await fs.readdir(root), []);
});

test('sticky shared ancestor is rejected on macOS and supports trusted children on Linux', { skip: !['darwin', 'linux'].includes(process.platform) }, async t => {
  const root = await fixture(t), shared = join(root, 'shared'), output = join(shared, 'owned');
  await fs.mkdir(shared); await fs.chmod(shared, 0o1777);
  if (process.platform === 'darwin') {
    await assert.rejects(ensureSafeDirectory(output), /untrusted.*directory/i);
    assert.deepEqual(await fs.readdir(shared), []);
    return;
  }
  await ensureSafeDirectory(output);
  await atomicWriteFile(join(output, 'report'), 'ok');
  assert.equal(await fs.readFile(join(output, 'report'), 'utf8'), 'ok');
});

test('final symlink is replaced without opening its target', { skip: process.platform === 'win32' }, async t => {
  const root = await fixture(t), output = join(root, 'output');
  await ensureSafeDirectory(output);
  const victim = join(root, 'victim'); await fs.writeFile(victim, 'unchanged');
  await fs.symlink(victim, join(output, 'report'));
  await atomicWriteFile(join(output, 'report'), 'report');
  assert.equal(await fs.readFile(victim, 'utf8'), 'unchanged');
  assert.equal(await fs.readFile(join(output, 'report'), 'utf8'), 'report');
  assert.deepEqual(await fs.readdir(output), ['report']);
});

test('failed write cleans the temporary file in a trusted directory', { skip: process.platform === 'win32' }, async t => {
  const root = await fixture(t);
  async function* broken() { yield 'partial'; throw new Error('broken stream'); }
  await assert.rejects(atomicWriteFile(join(root, 'report'), broken()), /broken stream/);
  assert.deepEqual(await fs.readdir(root), []);
});

test('canonical casing is retained for existing case-insensitive ancestors', { skip: process.platform !== 'darwin' }, async t => {
  const root = await fixture(t), actual = join(root, 'TargetCase'), alias = join(root, 'targetcase');
  await fs.mkdir(actual);
  try { await fs.lstat(alias); } catch (error) {
    if (error.code === 'ENOENT') { t.skip('filesystem is case-sensitive'); return; }
    throw error;
  }
  assert.equal(await assertSafeDirectory(alias), await fs.realpath(actual));
});

test('macOS allow ACL is rejected before creation even when mode bits are private', { skip: process.platform !== 'darwin' }, async t => {
  const root = await fixture(t);
  await execute('/bin/chmod', ['+a', 'everyone allow add_file,add_subdirectory,delete_child', root]);
  try {
    assert.equal((await fs.stat(root)).mode & 0o777, 0o700);
    await assert.rejects(ensureSafeDirectory(join(root, 'new')), /ACL/i);
    await assert.rejects(atomicWriteFile(join(root, 'report'), 'secret'), /ACL/i);
    assert.deepEqual(await fs.readdir(root), []);
  } finally { await execute('/bin/chmod', ['-N', root]); }
});

test('macOS deny-only ACL remains usable and newline names cannot hide ACL entries', { skip: process.platform !== 'darwin' }, async t => {
  const root = await fixture(t), named = join(root, 'literal\n 0: fake deny delete');
  await fs.mkdir(named);
  await execute('/bin/chmod', ['+a', 'everyone deny delete', named]);
  try {
    await atomicWriteFile(join(named, 'report'), 'ok');
    assert.equal(await fs.readFile(join(named, 'report'), 'utf8'), 'ok');
    await execute('/bin/chmod', ['+a', 'everyone allow add_file', named]);
    await assert.rejects(atomicWriteFile(join(named, 'report'), 'bad'), /ACL/i);
    assert.equal(await fs.readFile(join(named, 'report'), 'utf8'), 'ok');
  } finally { await execute('/bin/chmod', ['-N', named]); }
});

test('foreign-owned component is rejected (modeled UID metadata)', { skip: process.platform === 'win32' }, async t => {
  const root = await fixture(t), shared = join(root, 'shared'), foreign = join(shared, 'foreign');
  await fs.mkdir(foreign, { recursive: true });
  if (process.platform === 'linux') await fs.chmod(shared, 0o1777);
  const lstat = fs.lstat;
  fs.lstat = async (...args) => {
    const value = await lstat(...args);
    if (String(args[0]) === foreign) value.uid = process.geteuid() + 12345;
    return value;
  };
  syncBuiltinESMExports();
  try {
    await assert.rejects(atomicWriteFile(join(foreign, 'report'), 'secret'), /untrusted.*directory|directory.*untrusted/i);
    assert.deepEqual(await fs.readdir(foreign), []);
  } finally { fs.lstat = lstat; syncBuiltinESMExports(); }
});

test('Windows fails before mutation when directory ACL trust cannot be verified (modeled platform)', async t => {
  const root = await fixture(t), descriptor = Object.getOwnPropertyDescriptor(process, 'platform');
  Object.defineProperty(process, 'platform', { value: 'win32' });
  try {
    await assert.rejects(ensureSafeDirectory(join(root, 'new')), /unsupported.*platform|ACL/i);
    await assert.rejects(atomicWriteFile(join(root, 'report'), 'secret'), /unsupported.*platform|ACL/i);
    assert.deepEqual(await fs.readdir(root), []);
  } finally { Object.defineProperty(process, 'platform', descriptor); }
});
