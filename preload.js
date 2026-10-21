const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  getVaultStatus: () => ipcRenderer.invoke('vault:status'),
  unlockVault: (masterPassword, confirmation) => ipcRenderer.invoke('vault:unlock', masterPassword, confirmation),
  lockVault: () => ipcRenderer.invoke('vault:lock'),
  recordActivity: () => ipcRenderer.invoke('vault:activity'),
  confirmPasswordCopy: () => ipcRenderer.invoke('vault:confirm-copy'),
  copyPassword: (password, token) => ipcRenderer.invoke('vault:copy-password', password, token),
  saveEntry: (entry) => ipcRenderer.invoke('vault:save-entry', entry),
  updateEntry: (id, entry) => ipcRenderer.invoke('vault:update-entry', id, entry),
  deleteEntry: (id) => ipcRenderer.invoke('vault:delete-entry', id),
  loadEntries: () => ipcRenderer.invoke('vault:load-entries'),
  onAutoLock: (callback) => {
    const listener = () => callback();
    ipcRenderer.on('vault:auto-locked', listener);
    return () => ipcRenderer.removeListener('vault:auto-locked', listener);
  }
});
