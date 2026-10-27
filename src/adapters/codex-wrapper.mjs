// Codex Security requires scan artifacts outside the repository and enclosing Git worktree.
// Keep native subprocesses in the parent's process group so the core's group kill reaches them.
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdtemp, cp, rm } from 'node:fs/promises';
import { finished } from 'node:stream/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let active;
let interrupted = 0;
for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
  process.on(signal, () => { interrupted = code; active?.kill(signal); });
}
async function native(options, label, argv) {
  const stdout = createWriteStream(join(options.artifactDir, `${label}.stdout.log`), { flags: 'wx', mode: 0o600 });
  const stderr = createWriteStream(join(options.artifactDir, `${label}.stderr.log`), { flags: 'wx', mode: 0o600 });
  const logs = Promise.all([finished(stdout), finished(stderr)]);
  // Attach rejection handling immediately; a log-open failure terminates the native child.
  logs.catch(() => active?.kill('SIGTERM'));
  const code = await new Promise((resolve, reject) => {
    active = spawn(options.command, [...options.args, ...argv], { shell: false, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true });
    active.stdout.pipe(stdout); active.stderr.pipe(stderr);
    active.stdout.pipe(process.stdout, { end: false }); active.stderr.pipe(process.stderr, { end: false });
    active.once('error', reject);
    active.once('close', (exitCode, signal) => { active = undefined; resolve(exitCode ?? (signal === 'SIGINT' ? 130 : 143)); });
  });
  await logs;
  return code;
}
async function main() {
  const options = JSON.parse(process.argv[2]);
  const temporary = await mkdtemp(join(tmpdir(), 'sec-hub-codex-'));
  const results = join(temporary, 'results');
  try {
    const scanCode = await native(options, 'scan', ['scan', options.target, '--output-dir', results, '--headless', '--json', ...(options.scanArgs ?? [])]);
    if (interrupted) return interrupted;
    let code = scanCode;
    if ([0, 1].includes(scanCode)) {
      const exportCode = await native(options, 'export', ['export', results, '--export-format', 'json', '--output', join(options.artifactDir, 'findings.json')]);
      if (exportCode !== 0) code = exportCode;
    }
    return interrupted || code;
  } finally {
    try {
      await cp(results, join(options.artifactDir, 'codex-results'), { recursive: true, dereference: false, errorOnExist: true, force: false });
    } catch (error) {
      if (error.code !== 'ENOENT') {
        // Keep the private mkdtemp tree when copying evidence fails; deleting it would lose the only native results.
        console.error(`Codex Security native results could not be copied; private temporary results retained at ${temporary}.`);
        throw error;
      }
    }
    await rm(temporary, { recursive: true, force: true });
  }
}
try { process.exitCode = await main(); }
catch { console.error('Codex Security wrapper failed; inspect retained native step logs.'); process.exitCode = 2; }
