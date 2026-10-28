import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { assertSafeDirectory, atomicWriteFile } from '../src/safe-io.mjs';

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'sec-hub-safe-io-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('POSIX literal-backslash symlink is rejected before safe checks and atomic writes', { skip: process.platform === 'win32' }, async t => {
  const root = await fixture(t);
  const base = join(root, 'decoy');
  const outside = join(root, 'outside');
  const linkedPath = join(base, 'a\\b');
  await mkdir(join(base, 'a', 'b'), { recursive: true });
  await mkdir(outside);
  await symlink(outside, linkedPath, 'dir');

  await assert.rejects(assertSafeDirectory(linkedPath), /symbolic link/i);
  await assert.rejects(atomicWriteFile(join(linkedPath, 'marker.txt'), 'must not escape'), /symbolic link/i);
  await assert.rejects(readFile(join(outside, 'marker.txt')), { code: 'ENOENT' });
});

test('POSIX literal-backslash real directory remains a valid single path component', { skip: process.platform === 'win32' }, async t => {
  const root = await fixture(t);
  const literalName = join(root, 'a\\b');
  await mkdir(literalName);

  await assertSafeDirectory(literalName);
  await atomicWriteFile(join(literalName, 'marker.txt'), 'inside the literal directory');
  assert.equal(await readFile(join(literalName, 'marker.txt'), 'utf8'), 'inside the literal directory');
});

test('ordinary directory symlinks remain rejected', async t => {
  const root = await fixture(t);
  const outside = join(root, 'outside');
  const link = join(root, 'link');
  await mkdir(outside);
  await symlink(outside, link, 'dir');

  await assert.rejects(assertSafeDirectory(link), /symbolic link/i);
  await assert.rejects(atomicWriteFile(join(link, 'marker.txt'), 'must not escape'), /symbolic link/i);
  await assert.rejects(readFile(join(outside, 'marker.txt')), { code: 'ENOENT' });
});
