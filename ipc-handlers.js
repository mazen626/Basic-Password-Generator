// IPC handlers for the main process: caller checks, the vault calls, copy and clipboard
// clearing, the idle lock, and the themed menu. Electron objects are passed in so the
// handlers can be tested without Electron (see test/ipc-handlers.test.js). main.js only
// creates the window and wires these up.
const crypto = require('node:crypto');
const path = require('node:path');

const DEFAULTS = {
  idleLockMs: 5 * 60 * 1000,
  clipboardClearMs: 10 * 1000,
  copyTokenMs: 30 * 1000,
  zoomStep: 0.5
};
const EDIT_ACTIONS = new Set(['undo', 'redo', 'cut', 'copy', 'paste', 'selectAll']);
// Copy tokens are tied to one entry ID, or to this marker for the generator's password.
const GENERATED = Symbol('generated password');
const COPY_DETAIL = 'Other apps or clipboard history may capture it. The clipboard is temporary, not secure storage.';

function createIpcHandlers({
  ipcMain,
  getVault,
  pageUrl,
  clipboard,
  dialog,
  shell,
  getFocusedWindow,
  getAllWindows,
  getWindowFor,
  quit,
  settings = {}
}) {
  const { idleLockMs, clipboardClearMs, copyTokenMs, zoomStep } = { ...DEFAULTS, ...settings };
  let operationQueue = Promise.resolve();
  let idleLockTimer = null;
  let lastActivityAt = 0;
  let clipboardClearTimer = null;
  let copiedPasswordDigest;
  let pendingCopy;
  let copyTokenTimer = null;

  function serializeVaultOperation(operation) {
    const result = operationQueue.then(operation, operation);
    operationQueue = result.catch(() => {});
    return result;
  }

  function isTrustedFrame(event) {
    const frame = event?.senderFrame;
    return Boolean(frame && frame === event.sender?.mainFrame && frame.url === pageUrl);
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

  function isUnlocked() {
    return Boolean(getVault()?.isUnlocked());
  }

  function clearIdleLock() {
    if (idleLockTimer) clearTimeout(idleLockTimer);
    idleLockTimer = null;
  }

  function armIdleLock() {
    clearIdleLock();
    if (!isUnlocked()) return;

    lastActivityAt = Date.now();
    idleLockTimer = setTimeout(lockIfIdle, idleLockMs);
  }

  function lockIfIdle() {
    if (!isUnlocked()) return;
    const remainingTime = idleLockMs - (Date.now() - lastActivityAt);
    if (remainingTime > 0) {
      clearIdleLock();
      idleLockTimer = setTimeout(lockIfIdle, remainingTime);
      return;
    }

    clearIdleLock();
    clearCopyConfirmation();
    getVault().lock();
    getAllWindows().forEach((win) => {
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
    pendingCopy = undefined;
  }

  function requireUnlocked() {
    if (!isUnlocked()) throw new Error('Unlock the vault first.');
  }

  // Shows the native confirmation and, if accepted, issues a one-time token for `target`.
  async function confirmCopy(target, message) {
    clearCopyConfirmation();
    const confirmation = await dialog.showMessageBox(getFocusedWindow(), {
      type: 'warning',
      buttons: ['Copy for 10 seconds', 'Cancel'],
      defaultId: 1,
      cancelId: 1,
      title: 'Copy password',
      message,
      detail: COPY_DETAIL
    });
    if (confirmation.response !== 0) return { success: false, cancelled: true };
    // The idle lock may have fired while the dialog was open.
    requireUnlocked();

    pendingCopy = { token: crypto.randomUUID(), target };
    copyTokenTimer = setTimeout(() => {
      pendingCopy = undefined;
      copyTokenTimer = null;
    }, copyTokenMs);
    return { success: true, token: pendingCopy.token };
  }

  async function confirmEntryCopy(entryId) {
    requireUnlocked();
    const site = await getVault().getEntrySite(entryId);
    return confirmCopy(entryId, `Copy the password for ${site}?`);
  }

  async function confirmGeneratedCopy() {
    requireUnlocked();
    return confirmCopy(GENERATED, 'Copy this generated password to the system clipboard?');
  }

  // Each token works once, only for the target it was confirmed for.
  function takeCopyToken(token, target) {
    if (!pendingCopy || typeof token !== 'string' || token !== pendingCopy.token || pendingCopy.target !== target) {
      throw new Error('Confirm the copy action first.');
    }
    clearCopyConfirmation();
  }

  function writeToClipboard(password) {
    clearCopiedPassword();
    clipboard.writeText(password);
    copiedPasswordDigest = crypto.createHash('sha256').update(password).digest();
    clipboardClearTimer = setTimeout(clearCopiedPassword, clipboardClearMs);
    return { success: true };
  }

  async function copyEntryPassword(entryId, token) {
    requireUnlocked();
    takeCopyToken(token, entryId);
    return writeToClipboard(await getVault().getEntryPassword(entryId));
  }

  function copyGeneratedPassword(text, token) {
    requireUnlocked();
    takeCopyToken(token, GENERATED);
    if (typeof text !== 'string' || text.length === 0 || text.length > 4096) {
      throw new Error('Password must contain 1 to 4096 characters.');
    }
    return writeToClipboard(text);
  }

  function runMenuAction(contents, action) {
    const win = getWindowFor(contents);
    if (EDIT_ACTIONS.has(action)) {
      contents[action]();
      return { success: true };
    }
    switch (action) {
      case 'zoomIn':
        contents.setZoomLevel(Math.min(contents.getZoomLevel() + zoomStep, 3));
        break;
      case 'zoomOut':
        contents.setZoomLevel(Math.max(contents.getZoomLevel() - zoomStep, -3));
        break;
      case 'resetZoom':
        contents.setZoomLevel(0);
        break;
      case 'toggleFullScreen':
        win?.setFullScreen(!win.isFullScreen());
        break;
      case 'minimize':
        win?.minimize();
        break;
      case 'quit':
        quit();
        break;
      default:
        return { success: false, error: 'Unknown menu action.' };
    }
    return { success: true };
  }

  function registerAll() {
    registerVaultHandler('vault:status', async () => ({ success: true, ...await getVault().getStatus() }));

    registerVaultHandler('vault:backup', async () => ({
      success: true,
      backupName: await getVault().createBackup()
    }));

    registerVaultHandler('vault:open-folder', async () => {
      const error = await shell.openPath(path.dirname(getVault().filePath));
      if (error) throw new Error(error);
      return { success: true };
    });

    registerVaultHandler('vault:unlock', async (masterPassword, confirmation) => {
      const result = await getVault().unlock(masterPassword, confirmation);
      armIdleLock();
      return { success: true, created: result.created, migrated: result.migrated };
    });

    registerVaultHandler('vault:lock', () => {
      clearIdleLock();
      clearCopyConfirmation();
      getVault().lock();
      return { success: true };
    });

    registerVaultHandler('vault:activity', () => {
      armIdleLock();
      return { success: true };
    });

    registerVaultHandler('vault:confirm-copy-entry', (entryId) => confirmEntryCopy(entryId));

    registerVaultHandler('vault:copy-entry-password', async (entryId, token) => {
      const result = await copyEntryPassword(entryId, token);
      armIdleLock();
      return result;
    });

    registerVaultHandler('vault:confirm-copy-generated', () => confirmGeneratedCopy());

    registerVaultHandler('vault:copy-generated', (text, token) => {
      const result = copyGeneratedPassword(text, token);
      armIdleLock();
      return result;
    });

    registerVaultHandler('vault:reveal-password', async (entryId) => {
      const password = await getVault().getEntryPassword(entryId);
      armIdleLock();
      return { success: true, password };
    });

    registerVaultHandler('vault:get-backup-codes', async (entryId) => {
      const codes = await getVault().getBackupCodes(entryId);
      armIdleLock();
      return { success: true, codes };
    });

    ipcMain.handle('window:menu-action', (event, action) => {
      if (!isTrustedFrame(event)) return { success: false, error: 'Unauthorized caller.' };
      return runMenuAction(event.sender, action);
    });

    registerVaultHandler('vault:save-entry', async (entry) => {
      await getVault().saveEntry(entry);
      armIdleLock();
      return { success: true };
    });

    registerVaultHandler('vault:update-entry', async (id, entry) => {
      await getVault().updateEntry(id, entry);
      armIdleLock();
      return { success: true };
    });

    registerVaultHandler('vault:set-backup-code-used', async (entryId, codeId, used) => {
      await getVault().setBackupCodeUsed(entryId, codeId, used);
      armIdleLock();
      return { success: true };
    });

    registerVaultHandler('vault:delete-entry', async (id) => {
      await getVault().deleteEntry(id);
      armIdleLock();
      return { success: true };
    });

    registerVaultHandler('vault:load-entries', async () => {
      const entries = await getVault().loadEntrySummaries();
      armIdleLock();
      return { success: true, entries };
    });
  }

  // Locks the vault and drops any pending copy, for window close and app quit.
  function shutDown({ clearClipboard = false } = {}) {
    clearIdleLock();
    clearCopyConfirmation();
    getVault()?.lock();
    if (clearClipboard) clearCopiedPassword();
  }

  return { registerAll, registerVaultHandler, isTrustedFrame, armIdleLock, lockIfIdle, shutDown };
}

// The app needs no camera, microphone, notifications or other permissions, so deny them all.
function denyAllPermissions(session) {
  session.setPermissionRequestHandler((webContents, permission, callback) => callback(false));
  session.setPermissionCheckHandler(() => false);
}

module.exports = { createIpcHandlers, denyAllPermissions, DEFAULTS };
