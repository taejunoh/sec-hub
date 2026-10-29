import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));

test('npm package contains the runnable CLI and excludes repository maintenance scripts and test fixtures', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'sec-hub-package-'));
  try {
    const packed = spawnSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', temp], {
      cwd: root,
      encoding: 'utf8',
      timeout: 60_000
    });
    assert.equal(packed.status, 0, packed.stderr || packed.stdout);
    const [{ filename }] = JSON.parse(packed.stdout);
    const archive = join(temp, filename);
    const extracted = join(temp, 'unpacked');
    await import('node:fs/promises').then(({ mkdir }) => mkdir(extracted));
    execFileSync('tar', ['-xzf', archive, '-C', extracted]);

    const packageRoot = join(extracted, 'package');
    const help = spawnSync(process.execPath, ['bin/sec-hub.mjs', '--help'], {
      cwd: packageRoot,
      encoding: 'utf8',
      timeout: 10_000
    });
    assert.equal(help.status, 0, help.stderr || help.stdout);
    assert.match(help.stdout, /Sec Hub|Usage|scan/i);

    await assert.rejects(readFile(join(packageRoot, 'scripts/live-verify-five.mjs')));
    await assert.rejects(readFile(join(packageRoot, 'scripts/combine-verified-runs.mjs')));
    await assert.rejects(readFile(join(packageRoot, 'test/helpers/php-header-server.mjs')));
    await assert.rejects(readFile(join(packageRoot, 'test/fixtures/live-five/package.json')));
    const packagedReadme = await readFile(join(packageRoot, 'README.md'));
    const sourceReadme = await readFile(join(root, 'README.md'));
    assert.deepEqual(packagedReadme, sourceReadme);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});
