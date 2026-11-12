// IPC handlers for the main process: caller checks, the vault calls, copy and clipboard
// clearing, restore tokens, the idle lock, and the themed menu. Electron objects are passed in
// so the handlers can be tested without Electron (see test/ipc-handlers.test.js). main.js only
// creates the window and wires these up.
const crypto = require('node:crypto');
const path = require('node:path');

const DEFAULTS = {
  idleLockMs: 5 * 60 * 1000,
  clipboardClearMs: 10 * 1000,
  copyTokenMs: 30 * 1000,
  restoreTokenMs: 2 * 60 * 1000,
  zoomStep: 0.5
};
const MAX_LISTED_BACKUPS = 1000;
const EDIT_ACTIONS = new Set(['undo', 'redo', 'cut', 'copy', 'paste', 'selectAll']);
// Copy tokens are tied to one entry ID, or to this marker for the generator's password.
const GENERATED = Symbol('generated password');
const COPY_DETAIL = 'Other apps or clipboard history may capture it. The clipboard is temporary, not secure storage.';
const RESTORE_TOKEN_ERROR = 'Preview the backup again before restoring.';
const RESTORE_CHANGED_ERROR = 'The vault changed while the confirmation was open. Preview the backup again.';
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const BACKUP_KIND_LABELS = {
  backup: 'Backup',
  'pre-upgrade': 'Pre-upgrade backup',
  'pre-restore': 'Pre-restore backup',
  'pre-password-change': 'Pre-password-change backup',
  'pre-import': 'Pre-import backup'
};

// "12 Nov 2026, 14:03" in local time, from a backup name's millisecond timestamp.
function formatBackupDate(ms) {
  const date = new Date(ms);
  const pad = (value) => String(value).padStart(2, '0');
  return `${date.getDate()} ${MONTHS[date.getMonth()]} ${date.getFullYear()}, ${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

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
  const { idleLockMs, clipboardClearMs, copyTokenMs, restoreTokenMs, zoomStep } = { ...DEFAULTS, ...settings };
  let operationQueue = Promise.resolve();
  let idleLockTimer = null;
  let lastActivityAt = 0;
  let clipboardClearTimer = null;
  let copiedPasswordDigest;
  let pendingCopy;
  let copyTokenTimer = null;
  let pendingRestore;
  let restoreTokenTimer = null;
  // Increases on every cancel event, so a restore can tell that one happened while its
  // confirmation was open (docs/PHASE-2A-DESIGN.md, part D, step 3).
  let restoreCancelCount = 0;

  function serializeVaultOperation(operation) {
    const result = operationQueue.then(operation, operation);
    operationQueue = result.catch(() => {});
    return result;
  }

  function isTrustedFrame(event) {
    const frame = event?.senderFrame;
    return Boolean(frame && frame === event.sender?.mainFrame && frame.url === pageUrl);
  }

  // `cancelsRestoreToken` is for handlers registered from other files (the CSV import) whose call
  // must drop any restore token, like lock and unlock do here.
  function registerVaultHandler(channel, operation, { cancelsRestoreToken = false } = {}) {
    ipcMain.handle(channel, async (event, ...args) => {
      if (!isTrustedFrame(event)) return { success: false, error: 'Unauthorized caller.' };

      try {
        return await serializeVaultOperation(() => {
          if (cancelsRestoreToken) cancelRestoreToken();
          return operation(...args);
        });
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
    cancelRestoreToken();
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

  // Restore tokens (docs/PHASE-2A-DESIGN.md, part C). A successful preview issues one, valid for
  // restoreTokenMs and used up by the restore (2A.3). Only one is outstanding at a time. It holds
  // what was previewed, never the password: the backup id and digest, the vault file's state,
  // whether the vault was unlocked, the date from the backup's name and the preview summary.
  function dropRestoreToken() {
    if (restoreTokenTimer) clearTimeout(restoreTokenTimer);
    restoreTokenTimer = null;
    pendingRestore = undefined;
  }

  // Lock, auto-lock, unlock, a password change, a CSV import, shutDown and any failed preview or
  // restore call this.
  function cancelRestoreToken() {
    dropRestoreToken();
    restoreCancelCount += 1;
  }

  function issueRestoreToken({ id, backupDigest, vaultState, unlocked, createdAt, summary }) {
    dropRestoreToken();
    pendingRestore = {
      token: crypto.randomUUID(),
      expiresAt: Date.now() + restoreTokenMs,
      id,
      backupDigest,
      vaultState,
      unlocked,
      createdAt,
      summary
    };
    restoreTokenTimer = setTimeout(dropRestoreToken, restoreTokenMs);
    return pendingRestore.token;
  }

  // Uses the token up whatever the outcome: a wrong, expired or mismatched token also drops the
  // outstanding one. Returns what was stored with it.
  function takeRestoreToken(token, id) {
    const pending = pendingRestore;
    dropRestoreToken();
    if (!pending || typeof token !== 'string' || token !== pending.token || pending.id !== id || Date.now() >= pending.expiresAt) {
      throw new Error(RESTORE_TOKEN_ERROR);
    }
    const { token: _token, expiresAt: _expiresAt, ...record } = pending;
    return record;
  }

  const restoreTokens = {
    issue: issueRestoreToken,
    take: takeRestoreToken,
    cancel: cancelRestoreToken,
    get cancelCount() { return restoreCancelCount; }
  };

  async function previewBackup(id, password) {
    // A new preview replaces the outstanding token, and a failed one leaves none.
    cancelRestoreToken();
    const vault = getVault();
    const { summary, digest } = await vault.previewBackup(id, password);
    const vaultState = await vault.getVaultState();
    const token = issueRestoreToken({
      id,
      backupDigest: digest,
      vaultState,
      unlocked: vault.isUnlocked(),
      createdAt: vault.validateBackupId(id).createdAt,
      summary
    });
    return { success: true, summary, token };
  }

  // Transactional restore (docs/PHASE-2A-DESIGN.md, part D). Works locked or unlocked. Order:
  //   1. check the argument types, then use the token up (whatever happens next);
  //   2. note the cancel count and the lock state, which must match the token's;
  //   3. native confirmation, built only from the token record;
  //   4. after it, stop if a cancel event happened or the lock state changed (the idle lock may
  //      fire while the dialog is open);
  //   5. vault.restoreBackup re-checks both files and writes, inside the write transaction;
  //   6. on success the vault is locked and copy and restore tokens are cleared.
  // Any failure cancels the restore token.
  async function restoreBackup(id, token) {
    const vault = getVault();
    try {
      vault.validateBackupId(id);
      if (typeof token !== 'string') throw new Error(RESTORE_TOKEN_ERROR);
      const record = takeRestoreToken(token, id);
      const cancelCount = restoreCancelCount;
      const unlocked = vault.isUnlocked();
      if (unlocked !== record.unlocked) throw new Error(RESTORE_TOKEN_ERROR);

      const confirmation = await dialog.showMessageBox(getFocusedWindow() ?? getAllWindows()[0] ?? null, {
        type: 'warning',
        buttons: ['Restore', 'Cancel'],
        defaultId: 1,
        cancelId: 1,
        noLink: true,
        title: 'Restore backup',
        ...describeRestore(vault, record)
      });
      if (confirmation.response !== 0) {
        armIdleLock();
        return { success: false, cancelled: true };
      }
      if (restoreCancelCount !== cancelCount || vault.isUnlocked() !== unlocked) {
        throw new Error(RESTORE_CHANGED_ERROR);
      }

      const { preRestoreBackup } = await vault.restoreBackup(id, {
        backupDigest: record.backupDigest,
        vaultState: record.vaultState
      });
      clearIdleLock();
      clearCopyConfirmation();
      cancelRestoreToken();
      vault.lock();
      return { success: true, restoredFrom: id, preRestoreBackup };
    } catch (error) {
      cancelRestoreToken();
      throw error;
    }
  }

  // The confirmation text, from the token record only: the date in the backup's name, its kind
  // and the previewed entry count.
  function describeRestore(vault, record) {
    const { kind } = vault.validateBackupId(record.id);
    const count = record.summary.entryCount;
    const entries = `${count} ${count === 1 ? 'entry' : 'entries'}`;
    const saved = record.vaultState === 'absent'
      ? 'There is no current vault file, so there is nothing to save first.'
      : 'The current vault is saved first, as a pre-restore backup. Changes made after this backup was created will be replaced.';
    return {
      message: `Replace the current vault with the backup from ${formatBackupDate(record.createdAt)} (${entries})?`,
      detail: [
        `Kind: ${BACKUP_KIND_LABELS[kind]}.`,
        saved,
        'The vault then locks. Unlock it with the master password that was in use when this backup was made.'
      ].join('\n')
    };
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

    // Read only, and works locked or unlocked (docs/PHASE-2A-DESIGN.md, part B). The scan itself
    // is uncapped; the window gets at most MAX_LISTED_BACKUPS items, valid ones first.
    registerVaultHandler('vault:list-backups', async () => {
      const items = await getVault().listBackups();
      armIdleLock();
      return {
        success: true,
        items: items.slice(0, MAX_LISTED_BACKUPS),
        truncated: items.length > MAX_LISTED_BACKUPS
      };
    });

    // Works locked or unlocked, gated by the backup's own password (part C). Writes nothing.
    registerVaultHandler('vault:preview-backup', async (id, password) => {
      const result = await previewBackup(id, password);
      armIdleLock();
      return result;
    });

    // Replaces vault.json with a previewed backup, after a native confirmation (part D). Works
    // locked or unlocked; the vault is always locked afterwards.
    registerVaultHandler('vault:restore-backup', (id, token) => restoreBackup(id, token));

    registerVaultHandler('vault:open-folder', async () => {
      const error = await shell.openPath(path.dirname(getVault().filePath));
      if (error) throw new Error(error);
      return { success: true };
    });

    registerVaultHandler('vault:unlock', async (masterPassword, confirmation) => {
      cancelRestoreToken();
      const result = await getVault().unlock(masterPassword, confirmation);
      armIdleLock();
      return { success: true, created: result.created, migrated: result.migrated };
    });

    registerVaultHandler('vault:lock', () => {
      clearIdleLock();
      clearCopyConfirmation();
      cancelRestoreToken();
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

    registerVaultHandler('vault:change-master-password', async (currentPassword, newPassword, confirmation) => {
      cancelRestoreToken();
      const { backupName } = await getVault().changeMasterPassword(currentPassword, newPassword, confirmation);
      clearCopyConfirmation();
      armIdleLock();
      return { success: true, backupName };
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

  // Locks the vault and drops any pending copy or restore token, for window close and app quit.
  function shutDown({ clearClipboard = false } = {}) {
    clearIdleLock();
    clearCopyConfirmation();
    cancelRestoreToken();
    getVault()?.lock();
    if (clearClipboard) clearCopiedPassword();
  }

  return { registerAll, registerVaultHandler, isTrustedFrame, armIdleLock, lockIfIdle, shutDown, restoreTokens };
}

// The app needs no camera, microphone, notifications or other permissions, so deny them all.
function denyAllPermissions(session) {
  session.setPermissionRequestHandler((webContents, permission, callback) => callback(false));
  session.setPermissionCheckHandler(() => false);
}

module.exports = { createIpcHandlers, denyAllPermissions, DEFAULTS };
