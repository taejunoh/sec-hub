import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('..', import.meta.url)));

test('CLI --version matches package.json version', async () => {
  const metadata = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
  const result = spawnSync(process.execPath, ['bin/sec-hub.mjs', '--version'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 10_000
  });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  assert.equal(result.stdout.trim(), metadata.version);
});
