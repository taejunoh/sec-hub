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
    checks: { rendererLoad: false, catalog: false, securityPreferences: false, folderSwitch: false, singleInstance: false, closedPort: false, executionUnavailable: false, nativeScan: false },
    urls,
  };
  let secondary;
  let secondaryExit;
  try {
    const preferences = window.webContents.getLastWebPreferences();
    summary.webPreferences = { sandbox: preferences.sandbox, contextIsolation: preferences.contextIsolation, nodeIntegration: preferences.nodeIntegration, webSecurity: preferences.webSecurity };
    const inspectRenderer = () => window.webContents.executeJavaScript(`(async () => ({ readyState: document.readyState, rows: document.querySelector('#artifact-list')?.children.length ?? 0, catalog: await (await fetch('/api/catalog')).json(), executionStatus: (await fetch('/api/execution')).status }))()`);
    const inspectNativeTitle = async (expected) => {
      const changeTitle = async (script) => {
        const changed = new Promise((resolve) => window.once('page-title-updated', () => setImmediate(resolve)));
        const document = await window.webContents.executeJavaScript(script);
        await bounded(changed, 3000, 'renderer_title_event_missing');
        return { document, native: window.getTitle() };
      };
      const english = await changeTitle(`(() => { const select = document.querySelector('#language-select'); select.value = 'en'; select.dispatchEvent(new Event('change', { bubbles: true })); return { language: document.documentElement.lang, selection: select.value, title: document.title }; })()`);
      const changed = await changeTitle(`document.title = 'SEC HUB / Smoke document title'`);
      return { expected, afterLanguage: english.native, afterDocumentTitle: changed.native, englishDocument: english.document, preserved: english.native === expected && changed.native === expected && english.document.language === 'en' && english.document.selection === 'en' && english.document.title === 'SEC HUB / Developer Workbench' };
    };
    let renderer;
    await bounded((async () => {
      while (true) {
        renderer = await inspectRenderer();
        if (renderer.rows > 0) break;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    })(), 15_000, 'renderer_not_ready');
    const rendererPrivileges = await window.webContents.executeJavaScript(`({
      nodeExposed: typeof require !== 'undefined' || typeof process !== 'undefined',
      ipcExposed: typeof ipcRenderer !== 'undefined',
      bridge: Object.keys(window.secHubDesktop ?? {}).sort(),
    })`);
    summary.rendererPrivileges = rendererPrivileges;
    summary.checks.securityPreferences = preferences.sandbox === true && preferences.contextIsolation === true
      && preferences.nodeIntegration === false && preferences.webSecurity === true
      && !rendererPrivileges.nodeExposed && !rendererPrivileges.ipcExposed
      && rendererPrivileges.bridge.join(',') === 'cancelScan,chooseFolder,getJob,getState,openSetup,refreshResults,startScan';
    const count = renderer.catalog.artifacts.filter((item) => item.state === 'ready').length;
    summary.renderer = { domContentLoaded: domLoaded(), catalogCount: count };
    summary.checks.rendererLoad = domLoaded() && ['interactive', 'complete'].includes(renderer.readyState) && renderer.rows > 0;
    summary.checks.catalog = count > 0 && renderer.executionStatus === 404;
    summary.checks.executionUnavailable = renderer.executionStatus === 404;
    summary.nativeTitles = { example: await inspectNativeTitle('Sec Hub — Example data · No new scan') };
    summary.checks.rendererLoad &&= summary.nativeTitles.example.preserved;
    const initial = controller.current.url;
    const selected = path.join(directory, 'controlled-results');
    await fs.mkdir(selected, { mode: 0o700 });
    await fs.copyFile(new URL('./sample/example/run.json', import.meta.url), path.join(selected, 'run.json'));
    selectFolder(selected);
    const switched = await actions.openSavedResults();
    const after = await inspectRenderer();
    summary.checks.folderSwitch = switched === true && controller.current.url !== initial && controller.current.example === false && after.catalog.artifacts.some((item) => item.state === 'ready') && after.executionStatus === 404 && await portClosed(initial);
    summary.nativeTitles.savedResults = await inspectNativeTitle('Sec Hub — Saved results');
    summary.checks.folderSwitch &&= summary.nativeTitles.savedResults.preserved;
    const project = path.join(directory, 'controlled-project');
    await fs.mkdir(project, { mode: 0o700 });
    // A pinned, harmless package coordinate exercises the official lookup without installing packages.
    await fs.writeFile(path.join(project, 'package-lock.json'), JSON.stringify({
      name: 'desktop-smoke', version: '1.0.0', lockfileVersion: 3, packages: {
        '': { name: 'desktop-smoke', version: '1.0.0', dependencies: { 'is-number': '7.0.0' } },
        'node_modules/is-number': { version: '7.0.0' },
      },
    }), { mode: 0o600 });
    const invoke = (source, gesture = false) => window.webContents.executeJavaScript(source, gesture);
    selectFolder(project);
    window.focus();
    const initialState = await invoke('window.secHubDesktop.getState()');
    const withoutGesture = await invoke('window.secHubDesktop.chooseFolder()');
    const chosen = await invoke('window.secHubDesktop.chooseFolder()', true);
    const injected = await invoke("window.secHubDesktop.startScan({ toolIds: ['osv'], aiConsent: false, path: '/arbitrary' })", true);
    summary.nativeScan = {
      installed: initialState.tools?.some((tool) => tool.id === 'osv' && tool.installation === 'installed' && tool.selectable),
      withoutGesture: withoutGesture.error?.code,
      chosen: chosen.folderLabel === 'controlled-project',
      selectionError: chosen.error?.code,
      injected: injected.error?.code,
    };
    if (!summary.nativeScan.installed || summary.nativeScan.withoutGesture !== 'forbidden'
      || !summary.nativeScan.chosen || summary.nativeScan.injected !== 'invalid_request') throw Error('native_scan_admission_failed');
    const start = await invoke("window.secHubDesktop.startScan({ toolIds: ['osv'], aiConsent: false })", true);
    if (!start.job) {
      summary.nativeScan.startError = start.error?.code;
      throw Error('native_scan_start_failed');
    }
    const job = await bounded((async () => {
      while (true) {
        const { job } = await invoke('window.secHubDesktop.getJob()');
        if (job && ['completed', 'failed', 'cancelled'].includes(job.state)) return job;
        await new Promise((resolve) => setTimeout(resolve, 150));
      }
    })(), 45_000, 'native_scan_deadline');
    const refresh = await invoke('window.secHubDesktop.refreshResults()');
    const artifactId = refresh.results?.find((item) => item.jobId === job.id)?.artifactId;
    const artifact = artifactId && await invoke(`fetch('/api/artifacts/${artifactId}').then((response) => response.json())`);
    const browserStatus = artifactId && (await fetch(new URL(`api/artifacts/${artifactId}`, controller.current.url))).status;
    const tool = artifact?.run?.tools?.find((entry) => entry.id === 'osv');
    summary.nativeScan = { ...summary.nativeScan, state: job.state, errorCode: job.errorCode, runStatus: job.runStatus, reportsReady: job.reportsReady, artifactId, browserStatus, toolStatus: tool?.status };
    summary.checks.nativeScan = job.state === 'completed' && job.runStatus === 'completed' && job.reportsReady
      && tool?.status === 'completed' && browserStatus === 404;
    const secondEvent = secondInstance();
    secondary = spawn(process.execPath, ['--sec-hub-smoke', '--sec-hub-smoke-secondary'], { env: process.env, stdio: 'ignore', windowsHide: true });
    secondaryExit = new Promise((resolve, reject) => {
      secondary.once('error', () => reject(Error('secondary_launch_failed')));
      secondary.once('exit', (code, signal) => { summary.secondary = { exitCode: code, signal }; resolve(code); });
    });
    const [exitCode] = await bounded(Promise.all([secondaryExit, secondEvent]), 12_000, 'secondary_instance_timeout');
    summary.checks.singleInstance = exitCode === 0 && summary.secondary.signal === null;
  } catch (error) {
    summary.error = typeof error?.message === 'string' && /^[a-z_]+$/.test(error.message) ? error.message : 'packaged_runtime_self_test_failed';
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
