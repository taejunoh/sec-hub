'use strict';
const { app, BrowserWindow, Menu, dialog, shell, session, ipcMain } = require('electron');
const fs = require('node:fs');
const { randomBytes } = require('node:crypto');
const path = require('node:path');
const { pathToFileURL } = require('node:url');

// Production ignores command-line paths/URLs. Diagnostics require both gates.
function smokeDirectory() {
  if (!process.argv.includes('--sec-hub-smoke')) return null;
  const value = process.env.SEC_HUB_DESKTOP_SMOKE_DIR;
  if (!value || !path.isAbsolute(value)) return null;
  try {
    const stat = fs.lstatSync(value);
    if (!stat.isDirectory() || stat.isSymbolicLink() || fs.realpathSync(value) !== path.resolve(value)) return null;
    if (process.getuid && (stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0)) return null;
    return value;
  } catch { return null; }
}
const smokeDir = smokeDirectory();
if (smokeDir) {
  const profile = path.join(smokeDir, 'profile');
  fs.mkdirSync(profile, { recursive: true, mode: 0o700 });
  app.setPath('userData', profile);
}
app.setName('Sec Hub');
const hasLock = app.requestSingleInstanceLock();
if (!hasLock) {
  app.quit();
} else {
  let window;
  let controller;
  let scanHost;
  let viewEpoch = 0;
  let activeUrl = null;
  let quitPromise;
  let allowQuit = false;
  let secondCount = 0;
  let secondWaiter;
  let loaded = false;
  let smokeSelection;
  let initializationComplete;
  const initialized = new Promise((resolve) => { initializationComplete = resolve; });
  const urls = [];
  const focus = () => {
    if (window && !window.isDestroyed()) { if (window.isMinimized()) window.restore(); window.show(); window.focus(); }
  };
  app.on('second-instance', () => { secondCount++; focus(); secondWaiter?.(); });

  const shutdown = () => {
    if (quitPromise) return quitPromise;
    quitPromise = (async () => {
      await initialized;
      try {
        const outcomes = await Promise.allSettled([scanHost?.close(), controller?.close()]);
        const failed = outcomes.find((outcome) => outcome.status === 'rejected');
        if (failed) throw failed.reason;
      }
      finally { if (window && !window.isDestroyed()) window.destroy(); }
    })();
    return quitPromise;
  };
  function requestQuit() {
    void shutdown().then(() => {
      if (!smokeDir) { allowQuit = true; app.quit(); }
    }).catch(() => { if (!smokeDir) app.exit(1); });
  }
  app.on('before-quit', (event) => { if (!allowQuit) { event.preventDefault(); requestQuit(); } });
  app.on('window-all-closed', requestQuit);
  app.on('activate', focus);

  async function friendlyFailure() {
    if (quitPromise || smokeDir) return;
    const answer = await dialog.showMessageBox(window, {
      type: 'error', title: 'Sec Hub', message: 'The saved results view could not be loaded.',
      detail: 'Reload the results, show the bundled example, or quit and reopen Sec Hub.',
      buttons: ['Reload results', 'Show example', 'Quit'], defaultId: 0, cancelId: 2,
    });
    if (answer.response === 0 && controller?.current) {
      try { activeUrl = controller.current.url; await window.loadURL(activeUrl); }
      catch { requestQuit(); }
    } else if (answer.response === 1) await controller?.showExample();
    else requestQuit();
  }
  async function start() {
    const [{ createViewerController, createNativeActions }, { isOwnedUrl, isTrustedSender }, { inspectDesktopTools }] = await Promise.all([
      import('./controller.mjs'), import('./policy.mjs'), import('./tools.mjs'),
    ]);
    const core = app.isPackaged ? path.join(process.resourcesPath, 'core') : path.resolve(__dirname, '..', '..');
    const [{ startDashboard }, { createDesktopScanController }] = await Promise.all(['server', 'desktop-execution'].map(
      (name) => import(pathToFileURL(path.join(core, 'src', 'dashboard', `${name}.mjs`)).href),
    ));
    const trusted = (url) => isOwnedUrl(url, activeUrl);
    const desktopToken = randomBytes(32).toString('hex');
    const runs = path.join(app.getPath('userData'), 'scan-results');
    const currentSession = session.fromPartition('sec-hub-desktop');
    currentSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    currentSession.setPermissionCheckHandler(() => false);
    currentSession.setDevicePermissionHandler(() => false);
    currentSession.on('will-download', (event) => event.preventDefault());
    currentSession.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, (details, callback) => callback({ cancel: !trusted(details.url) }));
    window = new BrowserWindow({
      width: 1440, height: 980, minWidth: 850, minHeight: 600, show: true,
      title: 'Sec Hub — Example data · No new scan',
      webPreferences: { session: currentSession, preload: path.join(__dirname, 'preload.cjs'), sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true, devTools: false },
    });
    window.on('close', (event) => { event.preventDefault(); requestQuit(); });
    const contents = window.webContents;
    currentSession.webRequest.onBeforeSendHeaders({ urls: ['http://127.0.0.1/*'] }, (details, callback) => {
      const requestHeaders = { ...details.requestHeaders };
      for (const key of Object.keys(requestHeaders)) if (key.toLowerCase() === 'x-sec-hub-desktop') delete requestHeaders[key];
      if (details.resourceType === 'xhr' && ['GET', 'HEAD'].includes(details.method) && trusted(details.url)
        && isTrustedSender({ sender: details.webContents, senderFrame: details.frame }, contents, currentSession, activeUrl)) {
        requestHeaders['X-Sec-Hub-Desktop'] = desktopToken;
      }
      callback({ requestHeaders });
    });
    contents.on('did-start-navigation', (_event, details, _inPlace, isMainFrame) => {
      if (typeof details === 'object' ? details.isMainFrame : isMainFrame) viewEpoch++;
    });
    const preventUntrusted = (event, destination) => {
      const url = typeof destination === 'string' ? destination : destination?.url ?? event.url;
      if (!trusted(url)) event.preventDefault();
    };
    contents.on('will-navigate', preventUntrusted);
    contents.on('will-frame-navigate', preventUntrusted);
    contents.on('will-redirect', preventUntrusted);
    contents.on('will-attach-webview', (event) => event.preventDefault());
    contents.setWindowOpenHandler(() => ({ action: 'deny' }));
    contents.on('dom-ready', () => { loaded = true; });
    window.on('page-title-updated', (event) => event.preventDefault());
    contents.on('render-process-gone', () => { void friendlyFailure(); });
    controller = createViewerController({
      sampleRuns: path.join(__dirname, 'sample', 'example'),
      startDashboard: async (options) => {
        const server = await startDashboard({ ...options, ...(scanHost ? { desktopCatalog: { runs, token: desktopToken } } : {}) });
        urls.push(server.url);
        const revoke = () => { if (activeUrl === server.url) { activeUrl = null; viewEpoch++; } };
        void server.closed.then(revoke, revoke);
        return server;
      },
      inspectDashboard: async (url) => {
        const response = await fetch(`${url}api/catalog`, { signal: AbortSignal.timeout(10_000) });
        if (!response.ok) throw Error('catalog unavailable');
        const catalog = await response.json();
        return { readyCount: catalog.artifacts.filter((item) => item.state === 'ready').length };
      },
      show: async ({ url, example }) => {
        activeUrl = url; loaded = false;
        await window.loadURL(url);
        window.setTitle(example ? 'Sec Hub — Example data · No new scan' : 'Sec Hub — Saved results');
      },
      notify: async (message) => {
        if (!smokeDir && !quitPromise) await dialog.showMessageBox(window, { type: 'warning', title: 'Sec Hub', message });
      },
    });
    const inspectTools = () => inspectDesktopTools(app.isPackaged ? process.resourcesPath : null);
    try {
      scanHost = await createDesktopScanController({
        runs,
        inspectTools,
        async pickFolder() {
          if (smokeDir && smokeSelection) { const selected = smokeSelection; smokeSelection = undefined; return selected; }
          const result = await dialog.showOpenDialog(window, { title: 'Choose a project folder', buttonLabel: 'Choose folder', properties: ['openDirectory'] });
          return result.canceled ? undefined : result.filePaths[0];
        },
        async confirmAI({ folderLabel, toolIds, signal }) {
          const result = await dialog.showMessageBox(window, {
            type: 'warning', title: 'Sec Hub', message: 'Run AI security tools?',
            detail: `${toolIds.join(', ')} may send code and related context from “${folderLabel}” to model providers and may incur charges. This approval applies to this run only.`,
            buttons: ['Cancel', 'Run AI tools'], defaultId: 0, cancelId: 0, signal,
          });
          return result.response === 1;
        },
        openExternal: (url) => shell.openExternal(url),
        async refreshCatalog(jobs, generation, current) {
          const result = await controller.refreshDesktopCatalog(jobs, generation, current);
          if (current()) window.setTitle('Sec Hub — Recent scans');
          return result;
        },
      });
    } catch { /* An unsafe/unavailable output root must not disable saved results viewing. */ }
    const unavailable = { error: { code: 'execution_unavailable' } };
    const channelArities = { getState: 0, chooseFolder: 0, startScan: 1, getJob: 0, cancelScan: 0, refreshResults: 0, openSetup: 2 };
    const focusedActions = new Set(['chooseFolder', 'startScan', 'openSetup']);
    for (const [method, arity] of Object.entries(channelArities)) {
      ipcMain.handle(`sec-hub:${method}`, async (event, ...args) => {
        const epoch = viewEpoch;
        const current = () => !quitPromise && epoch === viewEpoch && isTrustedSender(event, contents, currentSession, activeUrl);
        try {
          if (!current() || (focusedActions.has(method) && !window.isFocused())) return { error: { code: 'forbidden' } };
          if (args.length !== arity) return { error: { code: 'invalid_request' } };
          if (!scanHost) {
            if (method !== 'getState') return unavailable;
            const tools = (await inspectTools()).map(({ id, installation, ai }) => ({ id, installation, ai, selectable: false, authentication: ai ? 'unknown' : 'not_required' }));
            return { folderLabel: null, tools, job: null, generation: 0 };
          }
          return await scanHost[method](...args, current);
        } catch { return { error: { code: 'internal_error' } }; }
      });
    }
    initializationComplete();
    if (quitPromise) return;
    const actions = createNativeActions({
      controller,
      pickFolder: async () => {
        if (smokeDir && smokeSelection) { const selected = smokeSelection; smokeSelection = undefined; return selected; }
        const result = await dialog.showOpenDialog(window, { title: 'Open saved results folder', buttonLabel: 'Open results', properties: ['openDirectory'] });
        return result.canceled ? undefined : result.filePaths[0];
      },
      openExternal: (url) => shell.openExternal(url),
    });
    const invoke = (operation) => () => { void operation().catch(() => friendlyFailure()); };
    Menu.setApplicationMenu(Menu.buildFromTemplate([
      ...(process.platform === 'darwin' ? [{ label: 'Sec Hub', submenu: [{ label: 'Quit Sec Hub', accelerator: 'Cmd+Q', click: requestQuit }] }] : []),
      { label: 'File', submenu: [
        { label: 'Open saved results folder…', accelerator: 'CmdOrCtrl+O', click: invoke(actions.openSavedResults) },
        { label: 'Show recent scans', enabled: Boolean(scanHost), click: invoke(async () => {
          const epoch = viewEpoch;
          const result = await scanHost.refreshResults(() => !quitPromise && epoch === viewEpoch);
          if (result.error) {
            await dialog.showMessageBox(window, { type: 'warning', title: 'Sec Hub', message: 'Recent scans are unavailable while a scan is running, or the results could not be loaded.' });
          } else await window.loadURL(activeUrl);
        }) },
        { label: 'Show example', click: invoke(() => controller.showExample()) },
        { label: 'Open saved view in browser', click: invoke(actions.openInBrowser) },
        { type: 'separator' }, { label: 'Quit', accelerator: 'Alt+F4', click: requestQuit },
      ] },
      { label: 'Edit', submenu: [{ role: 'copy' }, { role: 'selectAll' }] },
    ]));
    if (!await controller.showExample()) {
      if (smokeDir) throw Error('sample_startup_failed');
      await friendlyFailure();
    }
    if (smokeDir) {
      const { runPackagedSmoke } = await import('./smoke.mjs');
      const code = await runPackagedSmoke({
        directory: smokeDir, window, controller, actions, urls,
        selectFolder: (value) => { smokeSelection = value; },
        domLoaded: () => loaded,
        secondInstance: () => { const initial = secondCount; return new Promise((resolve) => { secondWaiter = () => { if (secondCount > initial) resolve(); }; }); },
        closeWindow: () => { window.close(); return shutdown(); },
      });
      if (code === 0) { allowQuit = true; app.quit(); }
      else app.exit(code);
    }
  }
  app.whenReady().then(start).catch(async () => {
    initializationComplete();
    await shutdown().catch(() => {});
    if (smokeDir) {
      const filename = path.join(smokeDir, 'summary.json');
      if (!fs.existsSync(filename)) fs.writeFileSync(filename, JSON.stringify({ status: 'failed', runtime: { electron: process.versions.electron, node: process.versions.node, platform: process.platform, arch: process.arch }, checks: {}, urls, error: 'desktop_startup_failed' }), { flag: 'wx', mode: 0o600 });
    } else await dialog.showMessageBox({ type: 'error', title: 'Sec Hub', message: 'Sec Hub could not open the saved results viewer. Quit and reopen the application.' });
    app.exit(1);
  });
}
