import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const native = new URL('../src/native/', import.meta.url);
const builder = fileURLToPath(new URL('build-darwin-acl-reader.mjs', native));
const clt = '/Library/Developer/CommandLineTools';
const onMac = process.platform === 'darwin';

function xcrun(args, developerDir) {
  return spawnSync('/usr/bin/xcrun', args, { encoding: 'utf8', env: { DEVELOPER_DIR: developerDir } });
}

function build(script, output, env) {
  return spawnSync(process.execPath, [script, output], { encoding: 'utf8', timeout: 30000, env });
}

async function scratch(t) {
  const path = await fs.mkdtemp(join(tmpdir(), 'sec-hub-acl-rebuild-'));
  t.after(() => fs.rm(path, { recursive: true, force: true }));
  return path;
}

test('pinned ACL builds are identical across source paths and destination names', { skip: !onMac }, async t => {
  const clang = xcrun(['clang', '--version'], clt);
  const sdk = xcrun(['--sdk', 'macosx', '--show-sdk-build-version'], clt);
  const ld = xcrun(['ld', '-v'], clt);
  if (!clang.stdout?.includes('(clang-2100.3.34.2)') || sdk.stdout?.trim() !== '26A425' ||
      !`${ld.stdout}${ld.stderr}`.includes('PROJECT:ld-27037.1')) {
    return t.skip('requires the pinned Apple Command Line Tools 27.0');
  }
  const first = await scratch(t);
  const second = join(await scratch(t), 'relocated checkout');
  await fs.mkdir(second);
  for (const file of ['build-darwin-acl-reader.mjs', 'darwin-acl-reader.c']) {
    await fs.copyFile(new URL(file, native), join(second, file));
  }

  const expected = join(first, 'darwin-acl-reader');
  const relocated = join(second, 'other name');
  const env = { DEVELOPER_DIR: clt };
  const initial = build(builder, expected, env);
  assert.equal(initial.status, 0, initial.error?.message || initial.stderr);
  const independent = build(join(second, 'build-darwin-acl-reader.mjs'), relocated, env);
  assert.equal(independent.status, 0, independent.error?.message || independent.stderr);
  assert.equal(JSON.parse(initial.stdout).binarySha256, JSON.parse(independent.stdout).binarySha256);
  assert.deepEqual(await fs.readFile(expected), await fs.readFile(relocated));

  const sys = join(second, 'sys');
  await fs.mkdir(sys);
  await fs.writeFile(join(sys, 'acl.h'), '#error inherited CPATH must not enter the build\n');
  const tainted = build(builder, relocated, { CPATH: second, SDKROOT: '/missing/sdk', MACOSX_DEPLOYMENT_TARGET: '99.0' });
  assert.equal(tainted.status, 0, tainted.error?.message || tainted.stderr);
  assert.deepEqual(await fs.readFile(expected), await fs.readFile(relocated));
  const verified = spawnSync('/usr/bin/codesign', ['--verify', '--strict', '--all-architectures', relocated], { encoding: 'utf8' });
  assert.equal(verified.status, 0, verified.stderr);
  assert.equal(JSON.parse(tainted.stdout).architectures, 'x86_64 arm64');
});

test('an unpinned selected toolchain is rejected before replacing the output', { skip: !onMac }, async t => {
  const selected = spawnSync('/usr/bin/xcode-select', ['-p'], { encoding: 'utf8', env: {} }).stdout?.trim();
  if (!selected) return t.skip('requires an installed alternative Apple toolchain');
  const clang = xcrun(['clang', '--version'], selected);
  if (clang.status !== 0 || clang.stdout.includes('(clang-2100.3.34.2)')) {
    return t.skip('requires an installed Apple toolchain with a different clang build');
  }
  const dir = await scratch(t);
  const output = join(dir, 'existing-helper');
  await fs.writeFile(output, 'keep previous output');
  const result = build(builder, output, { DEVELOPER_DIR: selected });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /requires the pinned Apple toolchain/);
  assert.equal(await fs.readFile(output, 'utf8'), 'keep previous output');
  assert.deepEqual(await fs.readdir(dir), ['existing-helper']);
});
