const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('node:path');
const PasswordVault = require('./vault');

let vault;
let operationQueue = Promise.resolve();

function serializeVaultOperation(operation) {
  const result = operationQueue.then(operation, operation);
  operationQueue = result.catch(() => {});
  return result;
}

function registerVaultHandler(channel, operation) {
  ipcMain.handle(channel, async (_event, ...args) => {
    try {
      return await serializeVaultOperation(() => operation(...args));
    } catch (error) {
      return { success: false, error: error.message };
    }
  });
}

registerVaultHandler('vault:unlock', async (masterPassword) => {
  const result = await vault.unlock(masterPassword);
  return { success: true, created: result.created };
});

registerVaultHandler('vault:lock', () => {
  vault.lock();
  return { success: true };
});

registerVaultHandler('vault:save-entry', async (entry) => {
  await vault.saveEntry(entry);
  return { success: true };
});

registerVaultHandler('vault:load-entries', async () => ({
  success: true,
  entries: await vault.loadEntries()
}));

function createWindow() {
  const win = new BrowserWindow({
    width: 520,
    height: 760,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  win.loadFile(path.join(__dirname, 'page.html'));
  win.on('closed', () => vault?.lock());
}

app.whenReady().then(() => {
  vault = new PasswordVault(path.join(app.getPath('userData'), 'vault.json'));
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => vault?.lock());

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
