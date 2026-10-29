import fs from 'node:fs/promises';
import path from 'node:path';
import { spawn } from 'node:child_process';
import net from 'node:net';

function bounded(promise, ms, code) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(Error(code)), ms); })]).finally(() => clearTimeout(timer));
}
export async function stopSecondary(child, exited) {
  if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
  child.kill();
  try { await bounded(exited, 1000, 'secondary_cleanup_timeout'); }
  catch {
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    await bounded(exited, 3000, 'secondary_cleanup_failed');
  }
}
export function portClosed(url) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port: Number(new URL(url).port) });
    socket.setTimeout(1000);
    socket.once('connect', () => { socket.destroy(); resolve(false); });
    socket.once('error', (error) => { socket.destroy(); resolve(error.code === 'ECONNREFUSED'); });
    socket.once('timeout', () => { socket.destroy(); resolve(false); });
  });
}

// Called only after main validates the explicit flag AND private harness directory.
export async function runPackagedSmoke({ directory, window, controller, actions, selectFolder, domLoaded, secondInstance, closeWindow, urls }) {
  const summary = {
    status: 'failed',
    runtime: { electron: process.versions.electron, node: process.versions.node, platform: process.platform, arch: process.arch },
    checks: { rendererLoad: false, catalog: false, securityPreferences: false, folderSwitch: false, singleInstance: false, closedPort: false, executionUnavailable: false },
    urls,
  };
  let secondary;
  let secondaryExit;
  try {
    const preferences = window.webContents.getLastWebPreferences();
    summary.webPreferences = { sandbox: preferences.sandbox, contextIsolation: preferences.contextIsolation, nodeIntegration: preferences.nodeIntegration };
    summary.checks.securityPreferences = preferences.sandbox === true && preferences.contextIsolation === true && preferences.nodeIntegration === false && preferences.webSecurity === true && !preferences.preload;
    const inspectRenderer = () => window.webContents.executeJavaScript(`(async () => ({ readyState: document.readyState, rows: document.querySelector('#artifact-list')?.children.length ?? 0, catalog: await (await fetch('/api/catalog')).json(), executionStatus: (await fetch('/api/execution')).status }))()`);
    let renderer;
    await bounded((async () => {
      while (true) {
        renderer = await inspectRenderer();
        if (renderer.rows > 0) break;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    })(), 15_000, 'renderer_not_ready');
    const count = renderer.catalog.artifacts.filter((item) => item.state === 'ready').length;
    summary.renderer = { domContentLoaded: domLoaded(), catalogCount: count };
    summary.checks.rendererLoad = domLoaded() && ['interactive', 'complete'].includes(renderer.readyState) && renderer.rows > 0;
    summary.checks.catalog = count > 0 && renderer.executionStatus === 404;
    summary.checks.executionUnavailable = renderer.executionStatus === 404;
    const initial = controller.current.url;
    const selected = path.join(directory, 'controlled-results');
    await fs.mkdir(selected, { mode: 0o700 });
    await fs.copyFile(new URL('./sample/example/run.json', import.meta.url), path.join(selected, 'run.json'));
    selectFolder(selected);
    const switched = await actions.openSavedResults();
    const after = await inspectRenderer();
    summary.checks.folderSwitch = switched === true && controller.current.url !== initial && controller.current.example === false && after.catalog.artifacts.some((item) => item.state === 'ready') && after.executionStatus === 404 && await portClosed(initial);
    const secondEvent = secondInstance();
    secondary = spawn(process.execPath, ['--sec-hub-smoke', '--sec-hub-smoke-secondary'], { env: process.env, stdio: 'ignore', windowsHide: true });
    secondaryExit = new Promise((resolve, reject) => {
      secondary.once('error', () => reject(Error('secondary_launch_failed')));
      secondary.once('exit', (code, signal) => { summary.secondary = { exitCode: code, signal }; resolve(code); });
    });
    const [exitCode] = await bounded(Promise.all([secondaryExit, secondEvent]), 12_000, 'secondary_instance_timeout');
    summary.checks.singleInstance = exitCode === 0 && summary.secondary.signal === null;
  } catch {
    summary.error = 'packaged_runtime_self_test_failed';
  } finally {
    try { await stopSecondary(secondary, secondaryExit); }
    catch { summary.error = 'packaged_secondary_cleanup_failed'; }
    try { await bounded(closeWindow(), 15_000, 'shutdown_timeout'); }
    catch { summary.error = 'packaged_runtime_shutdown_failed'; }
    summary.checks.closedPort = urls.length > 0 && (await Promise.all(urls.map(portClosed))).every(Boolean);
    if (Object.values(summary.checks).every((value) => value === true) && !summary.error) summary.status = 'passed';
    await fs.writeFile(path.join(directory, 'summary.json'), `${JSON.stringify(summary, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  }
  return summary.status === 'passed' ? 0 : 1;
}
