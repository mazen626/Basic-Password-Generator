const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('electronAPI', {
  saveOutput: (content) => ipcRenderer.invoke('save-output', content)
});
