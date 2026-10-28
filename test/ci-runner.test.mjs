import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runTestFiles } from '../scripts/ci.mjs';

// A child test failure must survive collection; TAP skips must not count as passes.
test('CI collection retains real TAP, stderr and unsuccessful child status', async t => {
  const root = await mkdtemp(join(tmpdir(), 'sec-hub-ci-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const fixture = join(root, 'fixture.test.mjs'), output = join(root, 'evidence');
  await writeFile(fixture, `import test from 'node:test';
    test('passing case', () => {});
    test('skipped case', { skip: true }, () => {});
    test('failure case', () => { console.error('synthetic diagnostic'); throw new Error('synthetic failure'); });`);
  const result = await runTestFiles({ files: [fixture], cwd: root, outputDirectory: output, quiet: true });
  assert.equal(result.exitCode, 1);
  assert.deepEqual(result.counts, { tests: 3, pass: 1, fail: 1, cancelled: 0, skipped: 1, todo: 0 });
  assert.match(await readFile(join(output, 'tests.tap'), 'utf8'), /synthetic failure/);
  assert.match(await readFile(join(output, 'tests.tap'), 'utf8'), /synthetic diagnostic/);
  const saved = JSON.parse(await readFile(join(output, 'tests-summary.json'), 'utf8'));
  assert.equal(saved.node, process.version);
  assert.equal(saved.platform, process.platform);
  assert.deepEqual(saved.files, [fixture]);
  assert.ok(Date.parse(saved.endedAt) >= Date.parse(saved.startedAt));
});
