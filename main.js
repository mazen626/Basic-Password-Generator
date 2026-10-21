const { app, BrowserWindow, clipboard, ipcMain } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const PasswordVault = require('./vault');

const PAGE_PATH = path.join(__dirname, 'page.html');
const PAGE_URL = pathToFileURL(PAGE_PATH).href;
const IDLE_LOCK_MS = 5 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 20 * 1000;

let vault;
let operationQueue = Promise.resolve();
let idleLockTimer;
let clipboardClearTimer;
let copiedPassword;

function serializeVaultOperation(operation) {
  const result = operationQueue.then(operation, operation);
  operationQueue = result.catch(() => {});
  return result;
}

function isTrustedFrame(event) {
  const frame = event.senderFrame;
  return Boolean(frame && frame === event.sender.mainFrame && frame.url === PAGE_URL);
}

function registerVaultHandler(channel, operation) {
  ipcMain.handle(channel, async (event, ...args) => {
    if (!isTrustedFrame(event)) return { success: false, error: 'Unauthorized caller.' };

    try {
      return await serializeVaultOperation(() => operation(...args));
    } catch (error) {
      return { success: false, error: error.message };
    }
  });
}

function clearIdleLock() {
  if (idleLockTimer) clearTimeout(idleLockTimer);
  idleLockTimer = null;
}

function armIdleLock() {
  clearIdleLock();
  if (!vault?.isUnlocked()) return;

  idleLockTimer = setTimeout(() => {
    vault.lock();
    idleLockTimer = null;
    BrowserWindow.getAllWindows().forEach((win) => {
      if (!win.isDestroyed()) win.webContents.send('vault:auto-locked');
    });
  }, IDLE_LOCK_MS);
}

function clearCopiedPassword() {
  if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
  clipboardClearTimer = null;

  if (copiedPassword !== undefined) {
    try {
      if (clipboard.readText() === copiedPassword) clipboard.clear();
    } catch {}
  }

  copiedPassword = undefined;
}

function copyPassword(password) {
  if (!vault?.isUnlocked()) throw new Error('Unlock the vault first.');
  if (typeof password !== 'string' || password.length === 0 || password.length > 4096) {
    throw new Error('Password must contain 1 to 4096 characters.');
  }

  clearCopiedPassword();
  clipboard.writeText(password);
  copiedPassword = password;
  clipboardClearTimer = setTimeout(clearCopiedPassword, CLIPBOARD_CLEAR_MS);
  return { success: true };
}

registerVaultHandler('vault:status', async () => ({
  success: true,
  exists: await vault.hasVault()
}));

registerVaultHandler('vault:unlock', async (masterPassword, confirmation) => {
  const result = await vault.unlock(masterPassword, confirmation);
  armIdleLock();
  return { success: true, created: result.created, migrated: result.migrated };
});

registerVaultHandler('vault:lock', () => {
  clearIdleLock();
  vault.lock();
  return { success: true };
});

registerVaultHandler('vault:activity', () => {
  armIdleLock();
  return { success: true };
});

registerVaultHandler('vault:copy-password', (password) => {
  const result = copyPassword(password);
  armIdleLock();
  return result;
});

registerVaultHandler('vault:save-entry', async (entry) => {
  await vault.saveEntry(entry);
  armIdleLock();
  return { success: true };
});

registerVaultHandler('vault:update-entry', async (id, entry) => {
  await vault.updateEntry(id, entry);
  armIdleLock();
  return { success: true };
});

registerVaultHandler('vault:delete-entry', async (id) => {
  await vault.deleteEntry(id);
  armIdleLock();
  return { success: true };
});

registerVaultHandler('vault:load-entries', async () => {
  const entries = await vault.loadEntries();
  armIdleLock();
  return { success: true, entries };
});

function createWindow() {
  const win = new BrowserWindow({
    width: 520,
    height: 760,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  win.webContents.on('will-navigate', (event, navigationUrl) => {
    if (navigationUrl !== PAGE_URL) event.preventDefault();
  });
  win.loadFile(PAGE_PATH);
  win.on('closed', () => {
    clearIdleLock();
    vault?.lock();
  });
}

app.whenReady().then(() => {
  vault = new PasswordVault(path.join(app.getPath('userData'), 'vault.json'));
  createWindow();

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => {
  clearIdleLock();
  vault?.lock();
  clearCopiedPassword();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
