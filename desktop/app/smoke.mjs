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
      const english = await changeTitle(`(() => {
        const select = document.querySelector('#language-select');
        select.value = 'en';
        select.dispatchEvent(new Event('change', { bubbles: true }));
        return {
          language: document.documentElement.lang,
          selection: select.value,
          title: document.title,
          heading: document.querySelector('.brand h1')?.textContent,
          scanIntro: document.querySelector('.scan-console-header > p')?.textContent,
        };
      })()`);
      const changed = await changeTitle(`document.title = 'Untrusted renderer title'`);
      const { language, selection, title, heading, scanIntro } = english.document;
      const preserved = english.native === expected && changed.native === expected && language === 'en' && selection === 'en'
        && title === 'Security Scan Hub / Developer Workbench' && heading === 'Security Scan Hub'
        && scanIntro === 'Run up to seven configured security tools in one scan. Review the results in one place.';
      return { expected, afterLanguage: english.native, afterDocumentTitle: changed.native, englishDocument: english.document, preserved };
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
      && rendererPrivileges.bridge.join(',') === 'cancelScan,chooseConfig,chooseFolder,chooseNode,getJob,getState,openSetup,refreshResults,startScan';
    const count = renderer.catalog.artifacts.filter((item) => item.state === 'ready').length;
    summary.renderer = { domContentLoaded: domLoaded(), catalogCount: count };
    summary.checks.rendererLoad = domLoaded() && ['interactive', 'complete'].includes(renderer.readyState) && renderer.rows > 0;
    summary.checks.catalog = count > 0 && renderer.executionStatus === 404;
    summary.checks.executionUnavailable = renderer.executionStatus === 404;
    summary.nativeTitles = { example: await inspectNativeTitle('Security Scan Hub — Example data · No new scan') };
    summary.checks.rendererLoad &&= summary.nativeTitles.example.preserved;
    const initial = controller.current.url;
    const selected = path.join(directory, 'controlled-results');
    await fs.mkdir(selected, { mode: 0o700 });
    const savedRun = JSON.parse(await fs.readFile(new URL('./sample/example/run.json', import.meta.url), 'utf8'));
    const dependency = savedRun.findings[0];
    dependency.location = { path: 'package-lock.json', package: 'npm:example', version: '1.0.0' };
    dependency.evidence = { affected: [{
      package: { name: 'example', ecosystem: 'npm' },
      ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.1.0' }] }],
    }] };
    savedRun.tools[0].findings[0] = dependency;
    const codeFinding = {
      toolId: 'open-code-review', ruleId: 'UI-003', title: 'Example suggested code',
      severity: 'medium', verification: 'candidate', location: { path: 'src/example.mjs', line: 1 },
      evidence: { suggestionCode: 'validate("<fixture>");' },
    };
    savedRun.findings.push(codeFinding);
    savedRun.tools.push({ id: 'open-code-review', selected: true, status: 'completed', findings: [codeFinding] });
    await fs.writeFile(path.join(selected, 'run.json'), JSON.stringify(savedRun), { mode: 0o600 });
    selectFolder(selected);
    const switched = await actions.openSavedResults();
    const after = await inspectRenderer();
    summary.checks.folderSwitch = switched === true && controller.current.url !== initial && controller.current.example === false && after.catalog.artifacts.some((item) => item.state === 'ready') && after.executionStatus === 404 && await portClosed(initial);
    summary.nativeTitles.savedResults = await inspectNativeTitle('Security Scan Hub — Saved results');
    summary.checks.folderSwitch &&= summary.nativeTitles.savedResults.preserved;
    summary.savedRecommendations = await bounded(window.webContents.executeJavaScript(`(async () => {
      document.querySelector('#artifact-list button')?.click();
      while (!document.querySelector('#finding-section .finding-select')) await new Promise((resolve) => setTimeout(resolve, 100));
      const openFinding = (title) => {
        Array.from(document.querySelectorAll('#finding-section .finding-select'))
          .find((button) => button.textContent.includes(title))?.click();
        return document.querySelector('#evidence-content .evidence-advisory');
      };
      const dependency = openFinding('Example dependency advisory');
      const fixedVersion = dependency?.textContent.includes('fixed version (1.1.0)') ?? false;
      const code = openFinding('Example suggested code');
      const suggestion = code?.querySelector('pre')?.textContent === 'validate("<fixture>");';
      return { fixedVersion, suggestion };
    })()`), 7000, 'saved_recommendations_missing');
    if (!summary.savedRecommendations.fixedVersion || !summary.savedRecommendations.suggestion) throw Error('saved_recommendations_mismatch');
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
    const waitFor = async (read, ms, code) => {
      const deadline = Date.now() + ms;
      while (Date.now() < deadline) {
        const value = await read();
        if (value) return value;
        await new Promise((resolve) => setTimeout(resolve, 150));
      }
      throw Error(code);
    };
    const click = (id) => invoke(`document.getElementById(${JSON.stringify(id)}).click()`, true);
    selectFolder(project);
    window.focus();
    const initialState = await invoke('window.secHubDesktop.getState()');
    const withoutGesture = await invoke('window.secHubDesktop.chooseFolder()');
    await waitFor(() => invoke("!document.getElementById('desktop-choose-folder').disabled"), 5000, 'scan_controls_unavailable');
    await click('desktop-choose-folder');
    const chosen = await waitFor(() => invoke("document.getElementById('desktop-folder').textContent === 'controlled-project'"), 5000, 'project_selection_failed');
    const injected = await invoke("window.secHubDesktop.startScan({ toolIds: ['osv'], aiConsent: false, path: '/arbitrary' })", true);
    const phpUrl = 'http://127.0.0.1:8080/';
    const checker = path.join(directory, 'phpcheck.js');
    const config = path.join(directory, 'trusted-tools.json');
    const node = process.env.SEC_HUB_DESKTOP_SMOKE_NODE;
    if (!path.isAbsolute(node ?? '')) throw Error('fixture_node_missing');
    // Only the adapter transport is under test here. The fixture makes no HTTP request.
    await fs.writeFile(checker, `if (process.argv[2] === '--version') console.log('PHP checker fixture 1.0.0');
      else if (process.argv[2] === ${JSON.stringify(phpUrl)} && process.argv[3] === '--json') {
        console.log(JSON.stringify({patch_status:'potentially_vulnerable',php_version:'8.4.1',reason:'Controlled smoke finding',exit_code:1}));
        process.exitCode = 1;
      } else process.exitCode = 2;`, { mode: 0o600 });
    await fs.writeFile(config, JSON.stringify({ tools: { php2shell: { command: node, args: [checker] } } }), { mode: 0o600 });
    selectFolder(config);
    await invoke("document.getElementById('desktop-config').open = true");
    await click('desktop-choose-config');
    const imported = await waitFor(() => invoke("document.getElementById('desktop-config-label').textContent === 'trusted-tools.json'"), 5000, 'config_import_failed');
    summary.nativeScan = {
      installed: initialState.tools?.some((tool) => tool.id === 'osv' && tool.installation === 'installed' && tool.selectable),
      withoutGesture: withoutGesture.error?.code,
      chosen,
      injected: injected.error?.code,
      configImported: imported,
    };
    if (!summary.nativeScan.installed || summary.nativeScan.withoutGesture !== 'forbidden'
      || !summary.nativeScan.chosen || summary.nativeScan.injected !== 'invalid_request' || !summary.nativeScan.configImported) throw Error('native_scan_admission_failed');
    await click('desktop-select-all');
    await invoke(`(() => {
      const input = document.getElementById('desktop-php-url');
      input.value = ${JSON.stringify(phpUrl)};
      input.dispatchEvent(new Event('input', { bubbles: true }));
    })()`);
    await click('execution-start');
    const job = await waitFor(async () => {
      const { job } = await invoke('window.secHubDesktop.getJob()');
      return job && ['completed', 'failed', 'cancelled'].includes(job.state) && job;
    }, 45_000, 'native_scan_deadline');
    const artifactId = await waitFor(() => invoke(`(async () => {
      const catalog = await (await fetch('/api/catalog')).json();
      const item = catalog.artifacts.find(({ summary }) => summary?.runId === ${JSON.stringify(job.resultRunId)});
      if (document.getElementById('detail-content').textContent.includes('Advertised PHP version may be vulnerable')) return item?.id;
    })()`), 7000, 'combined_report_not_opened');
    const artifact = artifactId && await invoke(`fetch('/api/artifacts/${artifactId}').then((response) => response.json())`);
    const browserStatus = artifactId && (await fetch(new URL(`api/artifacts/${artifactId}`, controller.current.url))).status;
    const tools = Object.fromEntries((artifact?.run?.tools ?? []).filter(({ selected }) => selected).map(({ id, status }) => [id, status]));
    const combinedFinding = artifact?.run?.findings?.some((finding) => finding.toolId === 'php2shell' && finding.ruleId === 'php2shell-header-version');
    const recommendationVisible = await invoke(`(() => {
      Array.from(document.querySelectorAll('#finding-section .finding-select'))
        .find((button) => button.textContent.includes('Advertised PHP version may be vulnerable'))?.click();
      const [check, action] = Array.from(document.querySelectorAll('#evidence-content .finding-action-steps > li'), (item) => item.textContent);
      return Boolean(check?.includes('Check first') && check.includes('actual PHP version')
        && action?.includes('Recommended action') && action.includes('If the installation is affected'));
    })()`);
    summary.nativeScan = { ...summary.nativeScan, state: job.state, errorCode: job.errorCode, runStatus: job.runStatus, reportsReady: job.reportsReady, artifactId, browserStatus, tools, combinedFinding, recommendationVisible };
    summary.checks.nativeScan = job.state === 'completed' && job.runStatus === 'completed' && job.reportsReady
      && tools.osv === 'completed' && tools.php2shell === 'completed' && combinedFinding && recommendationVisible && browserStatus === 404;
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
