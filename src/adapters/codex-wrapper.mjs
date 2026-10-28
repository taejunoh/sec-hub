// Codex Security requires scan artifacts outside the repository and enclosing Git worktree.
// Keep native subprocesses in the parent's process group so the core's group kill reaches them.
import { spawn } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { mkdtemp, cp, rm, stat, realpath, lstat } from 'node:fs/promises';
import { finished } from 'node:stream/promises';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, relative, isAbsolute, sep } from 'node:path';
import { createRedactor } from '../redaction.mjs';
const redact = createRedactor();

let active;
let interrupted = 0;
for (const [signal, code] of [['SIGINT', 130], ['SIGTERM', 143]]) {
  process.on(signal, () => { interrupted = code; process.exitCode = code; active?.kill(signal); });
}
function inside(parent, child) {
  const rel = relative(parent, child);
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${sep}`) && !isAbsolute(rel));
}
async function canonicalPath(path) {
  const absolute = resolve(path);
  try { return await realpath(absolute); }
  catch (error) {
    if (error.code !== 'ENOENT' && error.code !== 'ENOTDIR') throw error;
    const parent = dirname(absolute);
    if (parent === absolute) throw error;
    return join(await canonicalPath(parent), relative(parent, absolute));
  }
}
async function safeTemporaryBase(target) {
  const base = await realpath(tmpdir()), source = await canonicalPath(target);
  const forbidden = [source];
  // Discover every enclosing worktree from filesystem markers. This deliberately
  // runs no Git command, so repository fsmonitor/hooks/config cannot execute.
  for (let directory = source; ; directory = dirname(directory)) {
    try { await lstat(join(directory, '.git')); forbidden.push(directory); }
    catch (error) { if (!['ENOENT', 'ENOTDIR'].includes(error.code)) throw error; }
    if (dirname(directory) === directory) break;
  }
  if (forbidden.some(directory => inside(directory, base))) {
    throw Object.assign(new Error('Temporary directory is inside the source target or an enclosing Git worktree; set TMPDIR to a writable directory outside the checkout.'), { code: 'UNSAFE_TMPDIR' });
  }
  return base;
}
async function native(options, label, argv) {
  if (interrupted) return interrupted;
  const stdout = createWriteStream(join(options.artifactDir, `${label}.stdout.log`), { flags: 'wx', mode: 0o600 });
  const stderr = createWriteStream(join(options.artifactDir, `${label}.stderr.log`), { flags: 'wx', mode: 0o600 });
  const logs = Promise.all([finished(stdout), finished(stderr)]);
  // Attach rejection handling immediately; a log-open failure terminates the native child.
  logs.catch(() => active?.kill('SIGTERM'));
  const code = await new Promise((resolve, reject) => {
    if (interrupted) { stdout.end(); stderr.end(); resolve(interrupted); return; }
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
  const temporary = await mkdtemp(join(await safeTemporaryBase(options.target), 'sec-hub-codex-'));
  const results = join(temporary, 'results');
  try {
    if (interrupted) return interrupted;
    const scanCode = await native(options, 'scan', ['scan', options.target, '--output-dir', results, '--headless', '--json', ...(options.scanArgs ?? [])]);
    if (interrupted) return interrupted;
    let code = scanCode;
    if ([0, 1].includes(scanCode)) {
      if (interrupted) return interrupted;
      const exportCode = await native(options, 'export', ['export', results, '--export-format', 'json', '--output', join(options.artifactDir, 'findings.json')]);
      if (exportCode !== 0) code = exportCode;
    }
    return interrupted || code;
  } finally {
    let resultsExist = false;
    try { await stat(results); resultsExist = true; }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (resultsExist) {
      try {
        await cp(results, join(options.artifactDir, 'codex-results'), { recursive: true, dereference: false, errorOnExist: true, force: false });
      } catch (error) {
        // Any failure after confirming the source exists may leave the only native evidence private.
        console.error(`Codex Security native results could not be copied; private temporary results retained at ${redact(temporary)}.`);
        throw error;
      }
    }
    await rm(temporary, { recursive: true, force: true });
  }
}
try { process.exitCode = await main(); }
catch (error) {
  const code = redact(/^[A-Z0-9_]{1,64}$/.test(error?.code ?? '') ? error.code : 'WRAPPER_ERROR');
  const detail = redact(String(error?.message ?? error)).slice(0, 1500);
  console.error(`Codex Security wrapper failed (${code}): ${detail}; inspect retained native step logs when available.`);
  process.exitCode = 2;
}
