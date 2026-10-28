import { spawn, execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const portableFiles = [
  'auth-privacy.test.mjs', 'cli-version.test.mjs', 'compare.test.mjs',
  'dashboard-i18n.test.mjs', 'dashboard-view-model.test.mjs',
  'high31-windows-process-tree.test.mjs', 'privacy-release022.test.mjs',
  'ci-runner.test.mjs',
];
const nativeWindowsCases = ['timeout', 'cancel', 'output-limit'].map(trigger => `Windows native: ${trigger} terminates a ready descendant heartbeat`);
nativeWindowsCases.push('Windows native: unsupported ACL trust rejects writes before mutation');

function sourceCommit(cwd) {
  try { return execFileSync('git', ['rev-parse', 'HEAD'], { cwd, encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] }).trim(); }
  catch { return null; }
}

// Explicit argv works on Windows too; no shell glob expansion is involved.
export async function runTestFiles({ files, cwd, outputDirectory, env = process.env, quiet = false }) {
  if (!files.length) throw new Error('The test selection is empty');
  await mkdir(outputDirectory, { recursive: true, mode: 0o700 });
  const startedAt = new Date().toISOString();
  const args = ['--test', '--test-reporter=tap', ...files];
  let tap = '', stderr = '', spawnError;
  const childEnv = { ...env };
  // A collector invoked by node:test still starts an independent TAP harness.
  delete childEnv.NODE_TEST_CONTEXT;
  const child = spawn(process.execPath, args, { cwd, env: childEnv, shell: false, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', chunk => { tap += chunk; if (!quiet) process.stdout.write(chunk); });
  child.stderr.on('data', chunk => { stderr += chunk; if (!quiet) process.stderr.write(chunk); });
  child.once('error', error => { spawnError = error.message; });
  const { code, signal } = await new Promise(resolveClose => child.once('close', (code, signal) => resolveClose({ code, signal })));
  const counts = Object.fromEntries(['tests', 'pass', 'fail', 'cancelled', 'skipped', 'todo'].map(key => [key, Number(tap.match(new RegExp(`^# ${key} (\\d+)$`, 'm'))?.[1] ?? NaN)]));
  const complete = Object.values(counts).every(Number.isFinite) && counts.tests > 0;
  const summary = {
    platform: process.platform, architecture: process.arch, node: process.version,
    sourceCommit: sourceCommit(cwd), startedAt, endedAt: new Date().toISOString(),
    command: process.execPath, args, files, counts,
    exitCode: code === 0 && complete && counts.fail === 0 && counts.cancelled === 0 ? 0 : code || 1,
    signal, ...(spawnError ? { spawnError } : {}), tapComplete: complete,
    logs: { tap: 'tests.tap', stderr: 'tests.stderr.log' },
  };
  await writeFile(join(outputDirectory, 'tests.tap'), tap);
  await writeFile(join(outputDirectory, 'tests.stderr.log'), stderr);
  await writeFile(join(outputDirectory, 'tests-summary.json'), JSON.stringify(summary, null, 2) + '\n');
  return summary;
}

async function main() {
  const mode = process.argv[2] ?? (process.platform === 'win32' ? 'windows' : 'full');
  if (!['full', 'windows'].includes(mode)) throw new Error('Usage: node scripts/ci.mjs [full|windows]');
  if (process.platform === 'win32' && mode !== 'windows') throw new Error('Windows supports only the portable CI subset');
  const destination = process.env.CI_ARTIFACT_DIR;
  if (!destination || !isAbsolute(destination)) throw new Error('CI_ARTIFACT_DIR must be an absolute evidence directory');
  const outputDirectory = resolve(destination);
  await mkdir(outputDirectory, { recursive: true, mode: 0o700 });
  const privateTemp = await realpath(await mkdtemp(join(tmpdir(), 'sec-hub-ci-')));
  try {
    const available = (await readdir(join(root, 'test'))).filter(name => name.endsWith('.test.mjs')).sort();
    const selected = mode === 'windows' ? portableFiles : available;
    for (const file of selected) if (!available.includes(file)) throw new Error(`Required test is missing: ${file}`);
    const summary = await runTestFiles({
      files: selected.map(file => join('test', file)), cwd: root, outputDirectory,
      env: { ...process.env, TMPDIR: privateTemp, TMP: privateTemp, TEMP: privateTemp },
    });
    summary.mode = mode;
    summary.scope = mode === 'full' ? 'Complete supported POSIX test suite' : 'Portable subset; Windows safe I/O remains unsupported';
    if (process.platform === 'win32') {
      const tap = await readFile(join(outputDirectory, 'tests.tap'), 'utf8');
      summary.nativeWindowsCases = nativeWindowsCases.map(name => ({ name, passed: tap.split('\n').some(line => /^ok \d+ - /.test(line) && line.slice(line.indexOf(' - ') + 3) === name) }));
      if (summary.nativeWindowsCases.some(item => !item.passed)) summary.exitCode = 1;
    }
    await writeFile(join(outputDirectory, 'tests-summary.json'), JSON.stringify(summary, null, 2) + '\n');
    process.exitCode = summary.exitCode;
  } finally { await rm(privateTemp, { recursive: true, force: true }); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => { console.error(error); process.exitCode = 1; });
}
