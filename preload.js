const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  unlockVault: (masterPassword) => ipcRenderer.invoke('vault:unlock', masterPassword),
  lockVault: () => ipcRenderer.invoke('vault:lock'),
  saveEntry: (entry) => ipcRenderer.invoke('vault:save-entry', entry),
  loadEntries: () => ipcRenderer.invoke('vault:load-entries')
});
