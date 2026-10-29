import { access, chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { connect } from 'node:net';
import { spawn } from 'node:child_process';
import { validatePaths } from './build.mjs';

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const requiredChecks = ['rendererLoad', 'catalog', 'securityPreferences', 'folderSwitch', 'singleInstance', 'closedPort', 'executionUnavailable'];
function ownedURL(value) {
  const url = new URL(value);
  if (url.protocol !== 'http:' || url.hostname !== '127.0.0.1' || !url.port || url.username || url.password) throw new Error('Smoke server must have an owned loopback URL');
  return url;
}
export function validateSummary(summary, lock, target) {
  if (summary?.status !== 'passed') throw new Error(`Packaged application smoke failed: ${summary?.error ?? summary?.errors?.join('; ') ?? 'missing success summary'}`);
  for (const check of requiredChecks) if (summary.checks?.[check] !== true) throw new Error(`Packaged application smoke check failed: ${check}`);
  const [platform, arch] = target.split('-');
  if (summary.runtime?.electron !== lock.electron || summary.runtime?.node !== lock.node || summary.runtime?.platform !== platform || summary.runtime?.arch !== arch) throw new Error('Packaged embedded runtime does not match the pinned native target');
  if (!Array.isArray(summary.urls) || summary.urls.length < 2) throw new Error('Smoke must record both original and switched server URLs');
  for (const url of summary.urls) ownedURL(url);
  if (summary.secondary?.exitCode !== 0 || summary.secondary?.signal !== null) throw new Error('Secondary packaged instance did not exit successfully');
}
export async function assertClosedPort(value) {
  const url = ownedURL(value);
  await new Promise((resolve, reject) => {
    const socket = connect({ host: '127.0.0.1', port: Number(url.port) });
    socket.setTimeout(2000);
    socket.once('connect', () => { socket.destroy(); reject(new Error(`Owned server still listening after packaged app exit: ${url.origin}`)); });
    socket.once('timeout', () => { socket.destroy(); reject(new Error(`Timed out checking closed owned port: ${url.origin}`)); });
    socket.once('error', error => error.code === 'ECONNREFUSED' ? resolve() : reject(error));
  });
}
async function terminate(child) {
  if (!child.pid) return;
  if (process.platform === 'win32') {
    await new Promise(resolve => { const kill = spawn('taskkill.exe', ['/PID', String(child.pid), '/T', '/F'], { stdio: 'ignore', windowsHide: true }); kill.once('error', resolve); kill.once('close', resolve); });
  } else {
    try { process.kill(-child.pid, 'SIGTERM'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
    await new Promise(resolve => setTimeout(resolve, 1000));
    try { process.kill(-child.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
}
export async function smoke({ executable, out, timeoutMs = 90000 }) {
  if (!path.isAbsolute(executable ?? '') || !path.isAbsolute(out ?? '')) throw new Error('--executable and --out must be absolute paths');
  await validatePaths({ repository, out, cache: out });
  await mkdir(out, { recursive: true });
  if ((await readdir(out)).length) throw new Error('--out must be an empty evidence directory');
  if (executable.endsWith('.app')) executable = path.join(executable, 'Contents/MacOS/SecHub');
  executable = await realpath(executable); await access(executable);
  if ((await lstat(executable)).isDirectory()) throw new Error('--executable must select the packaged app executable');
  if ((process.platform === 'darwin' && path.basename(executable) !== 'SecHub') || (process.platform === 'win32' && path.basename(executable) !== 'Sec Hub.exe')) throw new Error('Smoke must launch the actual named packaged executable');
  await mkdir(out, { recursive: true });
  const harness = await mkdtemp(path.join(out, 'private-smoke-')); await chmod(harness, 0o700);
  const env = { ...process.env, SEC_HUB_DESKTOP_SMOKE_DIR: harness };
  for (const key of ['ELECTRON_RUN_AS_NODE', 'NODE_OPTIONS', 'NODE_PATH', 'ELECTRON_EXTRA_LAUNCH_ARGS']) delete env[key];
  // Open both logs before spawning. No stream error can strand a launched app.
  const stdout = await open(path.join(out, 'application-stdout.log'), 'wx', 0o600);
  let stderr;
  try { stderr = await open(path.join(out, 'application-stderr.log'), 'wx', 0o600); }
  catch (error) { await stdout.close(); throw error; }
  const startedAt = new Date().toISOString();
  const child = spawn(executable, ['--sec-hub-smoke'], { env, cwd: path.dirname(executable), stdio: ['ignore', stdout.fd, stderr.fd], detached: process.platform !== 'win32', windowsHide: false });
  let timedOut = false;
  let exit;
  try {
    exit = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => { timedOut = true; terminate(child).catch(reject); }, timeoutMs);
      child.once('error', error => { clearTimeout(timer); reject(error); });
      child.once('close', (exitCode, signal) => { clearTimeout(timer); resolve({ exitCode, signal }); });
    });
    if (timedOut) throw new Error(`Packaged application exceeded ${timeoutMs} ms smoke timeout`);
    if (exit.exitCode !== 0 || exit.signal !== null) throw new Error(`Packaged application exited unsuccessfully: ${JSON.stringify(exit)}`);
    const summaryPath = path.join(harness, 'summary.json');
    const info = await lstat(summaryPath);
    if (!info.isFile() || info.isSymbolicLink() || info.size > 1024 * 1024) throw new Error('Invalid smoke summary file');
    const summary = JSON.parse(await readFile(summaryPath, 'utf8'));
    const lock = JSON.parse(await readFile(path.join(repository, 'desktop/runtime-lock.json'), 'utf8'));
    validateSummary(summary, lock, `${process.platform}-${process.arch}`);
    for (const url of summary.urls) await assertClosedPort(url);
    const evidence = { status: 'passed', executable, args: ['--sec-hub-smoke'], startedAt, completedAt: new Date().toISOString(), observedPrimaryExit: exit, observedSecondaryExit: summary.secondary, independentClosedPorts: summary.urls, summaryPath, summary };
    await writeFile(path.join(out, 'smoke-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);
    return evidence;
  } catch (error) {
    if (!exit) await terminate(child);
    await writeFile(path.join(out, 'smoke-failure.json'), `${JSON.stringify({ status: 'failed', executable, startedAt, observedPrimaryExit: exit, summaryPath: path.join(harness, 'summary.json'), error: error.message }, null, 2)}\n`);
    throw error;
  } finally { await Promise.all([stdout.close(), stderr.close()]); }
}
function argumentsFor(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i++) {
    if (['--executable', '--out'].includes(argv[i]) && argv[i + 1]) options[argv[i].slice(2)] = argv[++i];
    else throw new Error(`Unknown or incomplete argument: ${argv[i]}`);
  }
  return options;
}
if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  smoke(argumentsFor(process.argv.slice(2))).then(result => console.log(JSON.stringify(result, null, 2))).catch(error => { console.error(error.message); process.exitCode = 1; });
}
