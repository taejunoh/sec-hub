'use strict';
const { contextBridge, ipcRenderer } = require('electron');

if (process.isMainFrame) {
  const invoke = (method, requiresGesture = false) => (...args) => {
    if (requiresGesture && !navigator.userActivation.isActive) return Promise.resolve({ error: { code: 'forbidden' } });
    return ipcRenderer.invoke(`sec-hub:${method}`, ...args);
  };
  contextBridge.exposeInMainWorld('secHubDesktop', Object.freeze({
    getState: invoke('getState'),
    chooseFolder: invoke('chooseFolder', true),
    startScan: invoke('startScan', true),
    getJob: invoke('getJob'),
    cancelScan: invoke('cancelScan'),
    refreshResults: invoke('refreshResults'),
    openSetup: invoke('openSetup', true),
  }));
}
