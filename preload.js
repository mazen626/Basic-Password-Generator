const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  platform: process.platform,
  menuAction: (action) => ipcRenderer.invoke('window:menu-action', action),
  getVaultStatus: () => ipcRenderer.invoke('vault:status'),
  backupVault: () => ipcRenderer.invoke('vault:backup'),
  openVaultFolder: () => ipcRenderer.invoke('vault:open-folder'),
  unlockVault: (masterPassword, confirmation) => ipcRenderer.invoke('vault:unlock', masterPassword, confirmation),
  lockVault: () => ipcRenderer.invoke('vault:lock'),
  recordActivity: () => ipcRenderer.invoke('vault:activity'),
  confirmPasswordCopy: () => ipcRenderer.invoke('vault:confirm-copy'),
  copyPassword: (password, token) => ipcRenderer.invoke('vault:copy-password', password, token),
  saveEntry: (entry) => ipcRenderer.invoke('vault:save-entry', entry),
  updateEntry: (id, entry) => ipcRenderer.invoke('vault:update-entry', id, entry),
  setBackupCodeUsed: (entryId, codeId, used) => ipcRenderer.invoke('vault:set-backup-code-used', entryId, codeId, used),
  deleteEntry: (id) => ipcRenderer.invoke('vault:delete-entry', id),
  loadEntries: () => ipcRenderer.invoke('vault:load-entries'),
  importCsv: () => ipcRenderer.invoke('vault:import-csv'),
  exportCsv: () => ipcRenderer.invoke('vault:export-csv'),
  onAutoLock: (callback) => {
    const listener = () => callback();
    ipcRenderer.on('vault:auto-locked', listener);
    return () => ipcRenderer.removeListener('vault:auto-locked', listener);
  }
});
