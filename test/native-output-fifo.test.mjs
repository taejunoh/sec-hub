import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { getAdapter } from '../src/adapters/index.mjs';

const fifoScript = `
  import { getAdapter } from ${JSON.stringify(new URL('../src/adapters/index.mjs', import.meta.url).href)};
  const [id, artifactDir] = process.argv.slice(1);
  try {
    await getAdapter(id).parse({ artifactDir, exitCode: 0, stdout: '', stderr: '' });
    process.stdout.write('parsed');
  } catch (error) {
    process.stdout.write(error.message);
  }
`;

async function parseWithDeadline(id, artifactDir, timeoutMs = 1200) {
  const child = spawn(process.execPath, ['--input-type=module', '-e', fifoScript, id, artifactDir], { stdio: ['ignore', 'pipe', 'pipe'] });
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8').on('data', chunk => { stdout += chunk; });
  child.stderr.setEncoding('utf8').on('data', chunk => { stderr += chunk; });
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      resolve({ timedOut: true, stdout, stderr });
    }, timeoutMs);
    child.once('error', error => { clearTimeout(timer); reject(error); });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ timedOut: false, code, signal, stdout, stderr });
    });
  });
}

test('native output FIFO paths reject promptly while regular JSON output still parses', { skip: process.platform === 'win32' }, async () => {
  const root = await mkdtemp(join(tmpdir(), 'sec-native-output-fifo-'));
  try {
    for (const [id, filename, payload] of [
      ['osv', 'native.json', { results: [] }],
      ['codex-security', 'findings.json', { documentType: 'codex-security.findings', schemaVersion: '1.0', scanId: 'test-scan', findings: [] }],
    ]) {
      const fifoDir = join(root, `${id}-fifo`);
      await mkdir(fifoDir);
      const fifoPath = join(fifoDir, filename);
      const made = spawnSync('mkfifo', [fifoPath], { encoding: 'utf8' });
      assert.equal(made.status, 0, made.stderr);
      const result = await parseWithDeadline(id, fifoDir);
      assert.equal(result.timedOut, false, `${id} parser blocked opening FIFO: ${result.stderr}`);
      assert.equal(result.code, 0, result.stderr);
      assert.match(result.stdout, /native JSON output file is missing or unsafe|exceeds limit or is not a file/);

      const regularDir = join(root, `${id}-regular`);
      await mkdir(regularDir);
      await writeFile(join(regularDir, filename), JSON.stringify(payload));
      const parsed = await getAdapter(id).parse({ artifactDir: regularDir, exitCode: 0, stdout: '', stderr: '' });
      assert.deepEqual(parsed, []);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
