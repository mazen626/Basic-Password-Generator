const { app, BrowserWindow, clipboard, dialog, ipcMain, powerMonitor, shell } = require('electron');
const crypto = require('node:crypto');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const PasswordVault = require('./vault');

const PAGE_PATH = path.join(__dirname, 'page.html');
const PAGE_URL = pathToFileURL(PAGE_PATH).href;
const IDLE_LOCK_MS = 5 * 60 * 1000;
const CLIPBOARD_CLEAR_MS = 10 * 1000;
const hasSingleInstanceLock = app.requestSingleInstanceLock();
if (!hasSingleInstanceLock) app.quit();

let vault;
let operationQueue = Promise.resolve();
let idleLockTimer;
let lastActivityAt = 0;
let clipboardClearTimer;
let copiedPasswordDigest;
let pendingCopyToken;
let copyTokenTimer;

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

  lastActivityAt = Date.now();
  idleLockTimer = setTimeout(lockIfIdle, IDLE_LOCK_MS);
}

function lockIfIdle() {
  if (!vault?.isUnlocked()) return;
  const remainingTime = IDLE_LOCK_MS - (Date.now() - lastActivityAt);
  if (remainingTime > 0) {
    clearIdleLock();
    idleLockTimer = setTimeout(lockIfIdle, remainingTime);
    return;
  }

  clearIdleLock();
  clearCopyConfirmation();
  vault.lock();
  BrowserWindow.getAllWindows().forEach((win) => {
    if (!win.isDestroyed()) win.webContents.send('vault:auto-locked');
  });
}

function clearCopiedPassword() {
  if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
  clipboardClearTimer = null;

  if (copiedPasswordDigest) {
    try {
      const clipboardDigest = crypto.createHash('sha256').update(clipboard.readText()).digest();
      if (crypto.timingSafeEqual(clipboardDigest, copiedPasswordDigest)) clipboard.clear();
      clipboardDigest.fill(0);
    } catch {}
  }

  copiedPasswordDigest?.fill(0);
  copiedPasswordDigest = undefined;
}

function clearCopyConfirmation() {
  if (copyTokenTimer) clearTimeout(copyTokenTimer);
  copyTokenTimer = null;
  pendingCopyToken = undefined;
}

async function confirmPasswordCopy() {
  if (!vault?.isUnlocked()) throw new Error('Unlock the vault first.');
  clearCopyConfirmation();
  const confirmation = await dialog.showMessageBox(BrowserWindow.getFocusedWindow(), {
    type: 'warning',
    buttons: ['Copy for 10 seconds', 'Cancel'],
    defaultId: 1,
    cancelId: 1,
    title: 'Copy password',
    message: 'Copy this password to the system clipboard?',
    detail: 'Other apps or clipboard history may capture it. The clipboard is temporary, not secure storage.'
  });
  if (confirmation.response !== 0) return { success: false, cancelled: true };

  pendingCopyToken = crypto.randomUUID();
  copyTokenTimer = setTimeout(() => {
    pendingCopyToken = undefined;
    copyTokenTimer = null;
  }, 30000);
  return { success: true, token: pendingCopyToken };
}

function copyPassword(password, token) {
  if (!vault?.isUnlocked()) throw new Error('Unlock the vault first.');
  if (!pendingCopyToken || token !== pendingCopyToken) throw new Error('Confirm the copy action first.');
  pendingCopyToken = undefined;
  if (copyTokenTimer) clearTimeout(copyTokenTimer);
  copyTokenTimer = null;
  if (typeof password !== 'string' || password.length === 0 || password.length > 4096) {
    throw new Error('Password must contain 1 to 4096 characters.');
  }

  clearCopiedPassword();
  clipboard.writeText(password);
  copiedPasswordDigest = crypto.createHash('sha256').update(password).digest();
  clipboardClearTimer = setTimeout(clearCopiedPassword, CLIPBOARD_CLEAR_MS);
  return { success: true };
}

registerVaultHandler('vault:status', async () => ({ success: true, ...await vault.getStatus() }));

registerVaultHandler('vault:backup', async () => ({
  success: true,
  backupName: await vault.createBackup()
}));

registerVaultHandler('vault:open-folder', async () => {
  const error = await shell.openPath(path.dirname(vault.filePath));
  if (error) throw new Error(error);
  return { success: true };
});

registerVaultHandler('vault:unlock', async (masterPassword, confirmation) => {
  const result = await vault.unlock(masterPassword, confirmation);
  armIdleLock();
  return { success: true, created: result.created, migrated: result.migrated };
});

registerVaultHandler('vault:lock', () => {
  clearIdleLock();
  clearCopyConfirmation();
  vault.lock();
  return { success: true };
});

registerVaultHandler('vault:activity', () => {
  armIdleLock();
  return { success: true };
});

registerVaultHandler('vault:confirm-copy', confirmPasswordCopy);

registerVaultHandler('vault:copy-password', (password, token) => {
  const result = copyPassword(password, token);
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
    title: 'VLAUTR',
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
    clearCopyConfirmation();
    vault?.lock();
  });
}

app.whenReady().then(() => {
  if (!hasSingleInstanceLock) return;
  powerMonitor.on('resume', lockIfIdle);
  powerMonitor.on('unlock-screen', lockIfIdle);
  vault = new PasswordVault(path.join(app.getPath('userData'), 'vault.json'));
  createWindow();

  app.on('second-instance', () => {
    const [win] = BrowserWindow.getAllWindows();
    if (!win) return;
    if (win.isMinimized()) win.restore();
    win.show();
    win.focus();
  });

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('before-quit', () => {
  clearIdleLock();
  clearCopyConfirmation();
  vault?.lock();
  clearCopiedPassword();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
