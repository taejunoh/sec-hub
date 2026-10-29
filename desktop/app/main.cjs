'use strict';
const { app, BrowserWindow, Menu, dialog, shell, session } = require('electron');
const fs = require('node:fs');
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
      try { await controller?.close(); }
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
    const [{ createViewerController, createNativeActions }, { isOwnedUrl }] = await Promise.all([
      import('./controller.mjs'), import('./policy.mjs'),
    ]);
    const core = app.isPackaged ? path.join(process.resourcesPath, 'core') : path.resolve(__dirname, '..', '..');
    const { startDashboard } = await import(pathToFileURL(path.join(core, 'src', 'dashboard', 'server.mjs')).href);
    const trusted = (url) => isOwnedUrl(url, activeUrl);
    const currentSession = session.defaultSession;
    currentSession.setPermissionRequestHandler((_contents, _permission, callback) => callback(false));
    currentSession.setPermissionCheckHandler(() => false);
    currentSession.setDevicePermissionHandler(() => false);
    currentSession.on('will-download', (event) => event.preventDefault());
    currentSession.webRequest.onBeforeRequest({ urls: ['<all_urls>'] }, (details, callback) => callback({ cancel: !trusted(details.url) }));
    window = new BrowserWindow({
      width: 1440, height: 980, minWidth: 850, minHeight: 600, show: true,
      title: 'Sec Hub — Example data · No new scan',
      webPreferences: { sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true, devTools: false },
    });
    window.on('close', (event) => { event.preventDefault(); requestQuit(); });
    const contents = window.webContents;
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
    contents.on('page-title-updated', (event) => event.preventDefault());
    contents.on('render-process-gone', () => { void friendlyFailure(); });
    controller = createViewerController({
      sampleRuns: path.join(__dirname, 'sample', 'example'),
      startDashboard: async (options) => {
        const server = await startDashboard(options);
        urls.push(server.url);
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
        { label: 'Show example', click: invoke(() => controller.showExample()) },
        { label: 'Open in browser', click: invoke(actions.openInBrowser) },
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
