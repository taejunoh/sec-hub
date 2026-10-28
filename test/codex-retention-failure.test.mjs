import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { spawn } from 'node:child_process';
import { getAdapter } from '../src/adapters/index.mjs';

async function invoke(spec, preload) {
  const args = preload
    ? ['--import', preload, ...spec.args]
    : spec.args;
  const options = JSON.parse(spec.args[1]);
  const child = spawn(spec.command, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env, EXAMPLE_API_TOKEN: 'synthetic-private-copy-secret', SEC_HUB_TEST_RESULTS_PATH: join(options.artifactDir, 'results-path.txt') },
  });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Codex wrapper exceeded test deadline')); }, 5000);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', exitCode => { clearTimeout(timer); resolve({ exitCode, stdout, stderr }); });
  });
}

test('Codex wrapper retains private results after copy failure and cleans up after success', async t => {
  const root = await mkdtemp(join(tmpdir(), 'sec-codex-retention-test-'));
  const canonicalTemp = await realpath(tmpdir());
  t.after(async () => {
    const resultsPath = await readFile(join(root, 'failed-copy', 'results-path.txt'), 'utf8').catch(() => '');
    if (resultsPath.startsWith(join(canonicalTemp, 'sec-hub-codex-'))) await rm(dirname(resultsPath), { recursive: true, force: true });
    await rm(root, { recursive: true, force: true });
  });
  const fake = join(root, 'fake-cs.mjs');
  await writeFile(fake, `
    import { mkdir, writeFile } from 'node:fs/promises';
    import { join } from 'node:path';
    const args = process.argv.slice(2);
    if (args[0] === 'scan') {
      const outputDir = args[args.indexOf('--output-dir') + 1];
      await mkdir(outputDir, { recursive: true });
      await writeFile(join(outputDir, 'partial-result.json'), '{"retained":true}');
      await writeFile(process.env.SEC_HUB_TEST_RESULTS_PATH, outputDir);
    } else if (args[0] === 'export') {
      await writeFile(args[args.indexOf('--output') + 1], '{}');
    } else process.exitCode = 2;
  `);
  const preload = join(root, 'fail-copy.mjs');
  await writeFile(preload, `
    import fs from 'node:fs/promises';
    import { syncBuiltinESMExports } from 'node:module';
    fs.cp = async () => { throw Object.assign(new Error('synthetic copy failure ' + process.env.EXAMPLE_API_TOKEN), { code: 'EIO' }); };
    syncBuiltinESMExports();
  `);

  async function specFor(label) {
    const artifactDir = join(root, label);
    await mkdir(artifactDir);
    const spec = getAdapter('codex-security').build({
      target: '/synthetic/repo',
      artifactDir,
      config: { tools: { 'codex-security': { command: process.execPath, args: [fake] } } },
    });
    return { artifactDir, spec };
  }

  const failed = await specFor('failed-copy');
  const failedRun = await invoke(failed.spec, preload);
  assert.equal(failedRun.exitCode, 2);
  assert.match(failedRun.stderr, /private temporary results retained at (.+)\./);
  assert.match(failedRun.stderr, /EIO.*synthetic copy failure/);
  assert.doesNotMatch(failedRun.stderr, /synthetic-private-copy-secret/);
  assert.ok(failedRun.stderr.length < 2500);
  const retainedPath = failedRun.stderr.match(/private temporary results retained at (.+)\./)[1];
  const resultsPath = await readFile(join(failed.artifactDir, 'results-path.txt'), 'utf8');
  assert.ok(retainedPath.startsWith(join(canonicalTemp, 'sec-hub-codex-')));
  assert.equal(dirname(resultsPath), retainedPath);
  assert.equal((await stat(retainedPath)).mode & 0o777, 0o700);
  assert.equal(await readFile(join(resultsPath, 'partial-result.json'), 'utf8'), '{"retained":true}');

  const successful = await specFor('successful-copy');
  const successfulRun = await invoke(successful.spec);
  assert.equal(successfulRun.exitCode, 0, successfulRun.stderr);
  assert.equal((await readdir(successful.artifactDir)).includes('codex-results'), true);
  const successfulResultsPath = await readFile(join(successful.artifactDir, 'results-path.txt'), 'utf8');
  await assert.rejects(stat(successfulResultsPath), { code: 'ENOENT' });

  // The wrapper-owned retained directory is deliberately removed only after its evidence is asserted.
  await rm(retainedPath, { recursive: true, force: true });
});
