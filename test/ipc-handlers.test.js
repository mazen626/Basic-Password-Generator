const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const { registerCsvHandlers } = require('../csv-transfer');
const { createIpcHandlers, denyAllPermissions, DEFAULTS } = require('../ipc-handlers');
const { MASTER_PASSWORD, createVault, makeEntry } = require('./helpers');

const PAGE_URL = 'file:///C:/app/page.html';
const CSV_CHANNELS = ['vault:import-csv', 'vault:export-csv'];

// Builds the real handlers around fake Electron objects. `answers` are the dialog buttons pressed, in order.
function harness(t, vault, { answers = [] } = {}) {
  const handlers = new Map();
  const sent = [];
  const calls = [];
  const clipboard = {
    text: '',
    readText() { return this.text; },
    writeText(value) { this.text = value; },
    clear() { this.text = ''; }
  };
  const frame = { url: PAGE_URL };
  const contents = {
    mainFrame: frame,
    zoom: 0,
    getZoomLevel() { return this.zoom; },
    setZoomLevel(level) { this.zoom = level; }
  };
  ['undo', 'redo', 'cut', 'copy', 'paste', 'selectAll'].forEach((name) => { contents[name] = () => calls.push(name); });
  const win = {
    fullScreen: false,
    isDestroyed: () => false,
    isFullScreen() { return this.fullScreen; },
    setFullScreen(value) { this.fullScreen = value; },
    minimize: () => calls.push('minimize'),
    webContents: { send: (channel) => sent.push(channel) }
  };
  const dialogs = [];

  const ipc = createIpcHandlers({
    ipcMain: {
      handle(channel, handler) {
        if (handlers.has(channel)) throw new Error(`${channel} registered twice`);
        handlers.set(channel, handler);
      }
    },
    getVault: () => vault,
    pageUrl: PAGE_URL,
    clipboard,
    dialog: {
      showMessageBox: async (parent, options) => {
        dialogs.push(options);
        return { response: answers.length ? answers.shift() : 0 };
      }
    },
    shell: { openPath: async () => '' },
    getFocusedWindow: () => win,
    getAllWindows: () => [win],
    getWindowFor: () => win,
    quit: () => calls.push('quit')
  });
  ipc.registerAll();
  // Clear the idle-lock, copy-token and clipboard timers so they do not keep the test process alive.
  t.after(() => ipc.shutDown({ clearClipboard: true }));

  const trusted = { senderFrame: frame, sender: contents };
  const invoke = (channel, ...args) => handlers.get(channel)(trusted, ...args);
  const invokeAs = (event, channel, ...args) => handlers.get(channel)(event, ...args);
  return { ipc, handlers, invoke, invokeAs, clipboard, contents, win, sent, calls, dialogs, frame };
}

test('registered channels plus CSV match exactly what preload.js calls', async (t) => {
  const { vault } = await createVault(t);
  const { handlers } = harness(t, vault);
  const preload = fs.readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8');
  const invoked = [...preload.matchAll(/ipcRenderer\.invoke\('([^']+)'/g)].map((m) => m[1]).sort();
  assert.deepEqual([...handlers.keys(), ...CSV_CHANNELS].sort(), invoked);
});

test('every channel rejects callers that are not the app page', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry());
  const h = harness(t, vault);
  const subframe = { url: PAGE_URL };
  const untrusted = [
    ['no sender frame', { sender: h.contents }],
    ['a subframe', { senderFrame: subframe, sender: h.contents }],
    ['another file', { senderFrame: { url: 'file:///C:/evil.html' }, sender: { mainFrame: { url: 'file:///C:/evil.html' } } }],
    ['a website', { senderFrame: { url: 'https://example.com/' }, sender: { mainFrame: { url: 'https://example.com/' } } }]
  ];
  untrusted[2][1].sender.mainFrame = untrusted[2][1].senderFrame;
  untrusted[3][1].sender.mainFrame = untrusted[3][1].senderFrame;

  for (const [label, event] of untrusted) {
    for (const channel of h.handlers.keys()) {
      const result = await h.invokeAs(event, channel, 'quit');
      assert.deepEqual(result, { success: false, error: 'Unauthorized caller.' }, `${channel} from ${label}`);
    }
  }
  assert.equal(vault.isUnlocked(), true, 'vault:lock from an untrusted caller must not lock');
  assert.equal(h.dialogs.length, 0, 'no dialog may open for an untrusted caller');
  assert.deepEqual(h.calls, [], 'no menu action or quit may run for an untrusted caller');
  assert.equal((await vault.loadEntries()).length, 1, 'no entry may change');
});

test('errors are returned as results, not thrown', async (t) => {
  const { vault } = await createVault(t, { unlocked: false });
  const h = harness(t, vault);
  assert.deepEqual(await h.invoke('vault:load-entries'), { success: false, error: 'Unlock the vault first.' });
  assert.deepEqual(await h.invoke('vault:delete-entry', 'not-an-id'), { success: false, error: 'Invalid entry id.' });
});

test('a failed call does not block the calls queued after it', async (t) => {
  const { vault } = await createVault(t);
  const h = harness(t, vault);
  const results = await Promise.all([
    h.invoke('vault:save-entry', makeEntry({ site: 'a.example' })),
    h.invoke('vault:save-entry', { site: '' }),
    h.invoke('vault:save-entry', makeEntry({ site: 'b.example' })),
    h.invoke('vault:load-entries')
  ]);
  assert.equal(results[0].success, true);
  assert.equal(results[1].success, false);
  assert.equal(results[2].success, true);
  assert.deepEqual(results[3].entries.map((entry) => entry.site).sort(), ['a.example', 'b.example']);
});

test('copying is refused while the vault is locked, without opening a dialog', async (t) => {
  const { vault } = await createVault(t, { unlocked: false });
  const h = harness(t, vault);
  assert.deepEqual(await h.invoke('vault:confirm-copy-generated'), { success: false, error: 'Unlock the vault first.' });
  assert.deepEqual(await h.invoke('vault:copy-generated', 'secret', 'any-token'), { success: false, error: 'Unlock the vault first.' });
  assert.equal(h.dialogs.length, 0);
  assert.equal(h.clipboard.text, '');
});

test('a copy needs a confirmed token, and each token works once', async (t) => {
  const { vault } = await createVault(t);
  const h = harness(t, vault);

  assert.deepEqual(await h.invoke('vault:copy-generated', 'secret', undefined), { success: false, error: 'Confirm the copy action first.' });
  assert.deepEqual(await h.invoke('vault:copy-generated', 'secret', 'made-up'), { success: false, error: 'Confirm the copy action first.' });
  assert.equal(h.clipboard.text, '');

  const { token } = await h.invoke('vault:confirm-copy-generated');
  assert.equal(h.dialogs[0].message, 'Copy this generated password to the system clipboard?');
  assert.deepEqual(await h.invoke('vault:copy-generated', 'secret', token), { success: true });
  assert.equal(h.clipboard.text, 'secret');
  assert.deepEqual(await h.invoke('vault:copy-generated', 'other', token), { success: false, error: 'Confirm the copy action first.' });
  assert.equal(h.clipboard.text, 'secret');
});

test('cancelling the dialog gives no token, and a new confirmation replaces the old token', async (t) => {
  const { vault } = await createVault(t);
  const h = harness(t, vault, { answers: [1, 0, 0] });

  assert.deepEqual(await h.invoke('vault:confirm-copy-generated'), { success: false, cancelled: true });
  const first = await h.invoke('vault:confirm-copy-generated');
  const second = await h.invoke('vault:confirm-copy-generated');
  assert.notEqual(first.token, second.token);
  assert.equal((await h.invoke('vault:copy-generated', 'secret', first.token)).success, false);
  assert.equal((await h.invoke('vault:copy-generated', 'secret', second.token)).success, true);
});

test('a copy token expires after 30 seconds, and locking drops it', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { vault } = await createVault(t);
  const h = harness(t, vault);

  const expiring = await h.invoke('vault:confirm-copy-generated');
  t.mock.timers.tick(DEFAULTS.copyTokenMs);
  assert.equal((await h.invoke('vault:copy-generated', 'secret', expiring.token)).success, false);

  const dropped = await h.invoke('vault:confirm-copy-generated');
  await h.invoke('vault:lock');
  await vault.unlock(MASTER_PASSWORD);
  assert.equal((await h.invoke('vault:copy-generated', 'secret', dropped.token)).success, false);
  assert.equal(h.clipboard.text, '');
});

test('copy rejects passwords that are not 1 to 4096 characters of text', async (t) => {
  const { vault } = await createVault(t);
  const h = harness(t, vault);
  for (const bad of ['', 'x'.repeat(4097), 42, null, { toString: () => 'secret' }]) {
    const { token } = await h.invoke('vault:confirm-copy-generated');
    assert.deepEqual(await h.invoke('vault:copy-generated', bad, token), { success: false, error: 'Password must contain 1 to 4096 characters.' });
  }
  assert.equal(h.clipboard.text, '');
});

test('the clipboard clears after 10 seconds only if it still holds the copied password', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { vault } = await createVault(t);
  const h = harness(t, vault);

  await h.invoke('vault:copy-generated', 'first-secret', (await h.invoke('vault:confirm-copy-generated')).token);
  t.mock.timers.tick(DEFAULTS.clipboardClearMs - 1);
  assert.equal(h.clipboard.text, 'first-secret');
  t.mock.timers.tick(1);
  assert.equal(h.clipboard.text, '');

  await h.invoke('vault:copy-generated', 'second-secret', (await h.invoke('vault:confirm-copy-generated')).token);
  h.clipboard.text = 'something the user copied';
  t.mock.timers.tick(DEFAULTS.clipboardClearMs);
  assert.equal(h.clipboard.text, 'something the user copied');
});

test('a second copy restarts the 10-second clear for the new password', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { vault } = await createVault(t);
  const h = harness(t, vault);

  await h.invoke('vault:copy-generated', 'one', (await h.invoke('vault:confirm-copy-generated')).token);
  t.mock.timers.tick(6000);
  await h.invoke('vault:copy-generated', 'two', (await h.invoke('vault:confirm-copy-generated')).token);
  t.mock.timers.tick(6000);
  assert.equal(h.clipboard.text, 'two');
  t.mock.timers.tick(4000);
  assert.equal(h.clipboard.text, '');
});

test('the vault locks after 5 minutes idle and tells the window', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { vault } = await createVault(t, { unlocked: false });
  const h = harness(t, vault);

  assert.equal((await h.invoke('vault:unlock', MASTER_PASSWORD, MASTER_PASSWORD)).success, true);
  t.mock.timers.tick(DEFAULTS.idleLockMs - 1);
  assert.equal(vault.isUnlocked(), true);
  t.mock.timers.tick(1);
  assert.equal(vault.isUnlocked(), false);
  assert.deepEqual(h.sent, ['vault:auto-locked']);
});

test('activity postpones the idle lock', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { vault } = await createVault(t, { unlocked: false });
  const h = harness(t, vault);

  await h.invoke('vault:unlock', MASTER_PASSWORD, MASTER_PASSWORD);
  t.mock.timers.tick(4 * 60 * 1000);
  await h.invoke('vault:activity');
  t.mock.timers.tick(4 * 60 * 1000);
  assert.equal(vault.isUnlocked(), true);
  t.mock.timers.tick(60 * 1000);
  assert.equal(vault.isUnlocked(), false);
});

test('resuming the computer locks a vault that has been idle too long', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { vault } = await createVault(t, { unlocked: false });
  const h = harness(t, vault);

  await h.invoke('vault:unlock', MASTER_PASSWORD, MASTER_PASSWORD);
  t.mock.timers.setTime(Date.now() + DEFAULTS.idleLockMs + 1);
  h.ipc.lockIfIdle();
  assert.equal(vault.isUnlocked(), false);
  assert.deepEqual(h.sent, ['vault:auto-locked']);

  h.ipc.lockIfIdle();
  assert.deepEqual(h.sent, ['vault:auto-locked'], 'an already locked vault sends nothing');
});

test('shutting down locks the vault and, on quit, clears a copied password', async (t) => {
  const { vault } = await createVault(t);
  const h = harness(t, vault);

  const { token } = await h.invoke('vault:confirm-copy-generated');
  h.ipc.shutDown();
  assert.equal(vault.isUnlocked(), false);
  await vault.unlock(MASTER_PASSWORD);
  assert.equal((await h.invoke('vault:copy-generated', 'secret', token)).success, false);

  await h.invoke('vault:copy-generated', 'secret', (await h.invoke('vault:confirm-copy-generated')).token);
  h.ipc.shutDown({ clearClipboard: true });
  assert.equal(h.clipboard.text, '');
});

test('menu actions run only known actions and keep zoom within limits', async (t) => {
  const { vault } = await createVault(t);
  const h = harness(t, vault);

  for (const action of ['undo', 'redo', 'cut', 'copy', 'paste', 'selectAll', 'minimize', 'quit']) {
    assert.deepEqual(await h.invoke('window:menu-action', action), { success: true });
  }
  assert.deepEqual(h.calls, ['undo', 'redo', 'cut', 'copy', 'paste', 'selectAll', 'minimize', 'quit']);

  for (let i = 0; i < 10; i += 1) await h.invoke('window:menu-action', 'zoomIn');
  assert.equal(h.contents.zoom, 3);
  for (let i = 0; i < 20; i += 1) await h.invoke('window:menu-action', 'zoomOut');
  assert.equal(h.contents.zoom, -3);
  await h.invoke('window:menu-action', 'resetZoom');
  assert.equal(h.contents.zoom, 0);
  await h.invoke('window:menu-action', 'toggleFullScreen');
  assert.equal(h.win.fullScreen, true);

  for (const bad of ['reload', 'openDevTools', 'constructor', '__proto__', '', null]) {
    assert.deepEqual(await h.invoke('window:menu-action', bad), { success: false, error: 'Unknown menu action.' });
  }
});

test('every Electron permission request and check is denied', () => {
  const session = {};
  session.setPermissionRequestHandler = (handler) => { session.request = handler; };
  session.setPermissionCheckHandler = (handler) => { session.check = handler; };
  denyAllPermissions(session);

  for (const permission of ['media', 'notifications', 'geolocation', 'clipboard-read', 'clipboard-sanitized-write', 'fullscreen', 'openExternal']) {
    let granted;
    session.request(null, permission, (value) => { granted = value; });
    assert.equal(granted, false, `${permission} request`);
    assert.equal(session.check(null, permission), false, `${permission} check`);
  }
});

// --- Phase 1 milestone 1.2: the window gets metadata only, and secrets one entry at a time ---

function findKeys(value, names, found = []) {
  if (Array.isArray(value)) value.forEach((item) => findKeys(item, names, found));
  else if (value && typeof value === 'object') {
    Object.entries(value).forEach(([key, child]) => {
      if (names.includes(key)) found.push(key);
      findKeys(child, names, found);
    });
  }
  return found;
}

async function savedEntryIds(vault) {
  const entries = await vault.loadEntries();
  return Object.fromEntries(entries.map((entry) => [entry.site, entry.id]));
}

test('vault:load-entries sends no passwords or backup codes, only counts', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example', password: 'pw-alpha-123', backupCodes: ['code-one', 'code-two'] }));
  await vault.saveEntry(makeEntry({ site: 'b.example', password: 'pw-beta-456' }));
  const ids = await savedEntryIds(vault);
  const firstCode = (await vault.getBackupCodes(ids['a.example']))[0];
  await vault.setBackupCodeUsed(ids['a.example'], firstCode.id, true);
  const h = harness(t, vault);

  const result = await h.invoke('vault:load-entries');
  assert.equal(result.success, true);
  assert.deepEqual(findKeys(result, ['password', 'code', 'codes']), []);
  const text = JSON.stringify(result);
  for (const secret of ['pw-alpha-123', 'pw-beta-456', 'code-one', 'code-two']) assert.equal(text.includes(secret), false, secret);

  const a = result.entries.find((entry) => entry.site === 'a.example');
  assert.equal(a.hasPassword, true);
  assert.deepEqual(a.backupCodes, { total: 2, unused: 1 });
  assert.deepEqual(result.entries.find((entry) => entry.site === 'b.example').backupCodes, { total: 0, unused: 0 });
});

test('vault:reveal-password returns one entry\'s password, and only while unlocked', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example', password: 'pw-alpha-123' }));
  const { 'a.example': id } = await savedEntryIds(vault);
  const h = harness(t, vault);

  assert.deepEqual(await h.invoke('vault:reveal-password', id), { success: true, password: 'pw-alpha-123' });
  assert.deepEqual(await h.invoke('vault:reveal-password', 'not-an-id'), { success: false, error: 'Invalid entry id.' });
  assert.deepEqual(await h.invoke('vault:reveal-password', '00000000-0000-4000-8000-000000000000'), { success: false, error: 'Entry not found.' });
  vault.lock();
  assert.deepEqual(await h.invoke('vault:reveal-password', id), { success: false, error: 'Unlock the vault first.' });
});

test('vault:get-backup-codes returns one entry\'s codes, and only while unlocked', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example', backupCodes: ['code-one', 'code-two'] }));
  const { 'a.example': id } = await savedEntryIds(vault);
  const h = harness(t, vault);

  const result = await h.invoke('vault:get-backup-codes', id);
  assert.equal(result.success, true);
  assert.deepEqual(result.codes.map(({ code, used }) => [code, used]), [['code-one', false], ['code-two', false]]);
  assert.deepEqual(Object.keys(result.codes[0]).sort(), ['code', 'id', 'used']);
  vault.lock();
  assert.deepEqual(await h.invoke('vault:get-backup-codes', id), { success: false, error: 'Unlock the vault first.' });
});

test('copying an entry names its site, then copies that entry\'s password from the vault', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'github.com', password: 'pw-github-789' }));
  const { 'github.com': id } = await savedEntryIds(vault);
  const h = harness(t, vault);

  const { token } = await h.invoke('vault:confirm-copy-entry', id);
  assert.equal(h.dialogs[0].message, 'Copy the password for github.com?');
  assert.deepEqual(await h.invoke('vault:copy-entry-password', id, token), { success: true });
  assert.equal(h.clipboard.text, 'pw-github-789');
  assert.equal((await h.invoke('vault:copy-entry-password', id, token)).success, false, 'tokens work once');

  t.mock.timers.tick(DEFAULTS.clipboardClearMs);
  assert.equal(h.clipboard.text, '');
});

test('a copy token only works for the entry, or the generator, it was confirmed for', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example', password: 'pw-alpha-123' }));
  await vault.saveEntry(makeEntry({ site: 'b.example', password: 'pw-beta-456' }));
  const ids = await savedEntryIds(vault);
  const h = harness(t, vault);
  const refused = { success: false, error: 'Confirm the copy action first.' };

  const forA = (await h.invoke('vault:confirm-copy-entry', ids['a.example'])).token;
  assert.deepEqual(await h.invoke('vault:copy-entry-password', ids['b.example'], forA), refused);
  assert.deepEqual(await h.invoke('vault:copy-generated', 'anything', forA), refused);

  const forGenerator = (await h.invoke('vault:confirm-copy-generated')).token;
  assert.deepEqual(await h.invoke('vault:copy-entry-password', ids['a.example'], forGenerator), refused);

  assert.deepEqual(await h.invoke('vault:copy-entry-password', ids['a.example'], undefined), refused);
  assert.equal(h.clipboard.text, '');
});

test('confirming a copy for a missing, malformed or locked entry opens no dialog', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example' }));
  const { 'a.example': id } = await savedEntryIds(vault);
  const h = harness(t, vault);

  assert.deepEqual(await h.invoke('vault:confirm-copy-entry', '00000000-0000-4000-8000-000000000000'), { success: false, error: 'Entry not found.' });
  assert.deepEqual(await h.invoke('vault:confirm-copy-entry', 'not-an-id'), { success: false, error: 'Invalid entry id.' });
  vault.lock();
  assert.deepEqual(await h.invoke('vault:confirm-copy-entry', id), { success: false, error: 'Unlock the vault first.' });
  assert.equal(h.dialogs.length, 0);
});

test('no copy token is issued if the vault locks while the dialog is open', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example' }));
  const { 'a.example': id } = await savedEntryIds(vault);
  const h = harness(t, vault);
  // The fake dialog records each dialog it opens. Lock the vault at that moment, as the idle lock would.
  h.dialogs.push = function push(options) {
    vault.lock();
    return Array.prototype.push.call(this, options);
  };

  assert.deepEqual(await h.invoke('vault:confirm-copy-entry', id), { success: false, error: 'Unlock the vault first.' });
  assert.equal(h.dialogs.length, 1);
});

test('editing without a password or codes keeps the saved ones', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example', password: 'pw-alpha-123', backupCodes: ['code-one'] }));
  const { 'a.example': id } = await savedEntryIds(vault);
  const h = harness(t, vault);

  const { password: _password, backupCodes: _codes, ...withoutSecrets } = makeEntry({ site: 'a.example', notes: 'edited' });
  assert.deepEqual(await h.invoke('vault:update-entry', id, withoutSecrets), { success: true });
  assert.deepEqual(await h.invoke('vault:reveal-password', id), { success: true, password: 'pw-alpha-123' });
  assert.deepEqual((await h.invoke('vault:get-backup-codes', id)).codes.map((code) => code.code), ['code-one']);
  assert.equal((await h.invoke('vault:load-entries')).entries[0].notes, 'edited');
});

// --- Phase 1 milestone 1.4: change master password ---

test('vault:change-master-password changes the password and drops any pending copy', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  const h = harness(t, vault);
  const { token } = await h.invoke('vault:confirm-copy-generated');

  const result = await h.invoke('vault:change-master-password', MASTER_PASSWORD, 'a brand new master password', 'a brand new master password');
  assert.equal(result.success, true);
  assert.match(result.backupName, /^vault-before-password-change-\d{13}-[0-9a-f-]{36}\.bak$/);
  assert.deepEqual(await h.invoke('vault:copy-generated', 'secret', token), { success: false, error: 'Confirm the copy action first.' });

  vault.lock();
  await assert.rejects(vault.unlock(MASTER_PASSWORD), /Incorrect master password/);
  await vault.unlock('a brand new master password');
  assert.ok(vaultPath);
});

test('vault:change-master-password reports errors and refuses a locked vault', async (t) => {
  const { vault } = await createVault(t);
  const h = harness(t, vault);
  assert.deepEqual(await h.invoke('vault:change-master-password', 'wrong password!', 'a brand new master password', 'a brand new master password'),
    { success: false, error: 'The current master password is incorrect.' });
  vault.lock();
  assert.deepEqual(await h.invoke('vault:change-master-password', MASTER_PASSWORD, 'a brand new master password', 'a brand new master password'),
    { success: false, error: 'Unlock the vault first.' });
});

// --- Phase 2A milestone 2A.1: backup list ---

const backupName = (ms, n) => `vault-backup-${ms}-${String(n).padStart(8, '0')}-0000-4000-8000-000000000000.bak`;

test('vault:list-backups works while locked and rejects other callers', async (t) => {
  const { vault } = await createVault(t);
  const made = await vault.createBackup();
  vault.lock();
  const h = harness(t, vault);

  const result = await h.invoke('vault:list-backups');
  assert.equal(result.success, true);
  assert.equal(result.truncated, false);
  assert.deepEqual(result.items.map((item) => [item.id, item.kind, item.status, item.passwordHint, item.version]),
    [[made, 'backup', 'valid', 'current', 3]]);
  assert.match(result.items[0].createdAt, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
  assert.equal(vault.isUnlocked(), false);

  const subframe = { senderFrame: { url: PAGE_URL }, sender: h.contents };
  assert.deepEqual(await h.invokeAs(subframe, 'vault:list-backups'), { success: false, error: 'Unauthorized caller.' });
});

test('vault:list-backups counts as activity while unlocked', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'] });
  const { vault } = await createVault(t, { unlocked: false });
  const h = harness(t, vault);

  await h.invoke('vault:unlock', MASTER_PASSWORD, MASTER_PASSWORD);
  t.mock.timers.tick(4 * 60 * 1000);
  assert.equal((await h.invoke('vault:list-backups')).success, true);
  t.mock.timers.tick(4 * 60 * 1000);
  assert.equal(vault.isUnlocked(), true);
  t.mock.timers.tick(60 * 1000);
  assert.equal(vault.isUnlocked(), false);
});

test('vault:list-backups sends at most 1,000 items, valid ones first, newest first', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const contents = await fs.promises.readFile(vaultPath);
  const start = 1762900000000;
  const valid = [];
  for (let n = 0; n < 1500; n++) {
    valid.push(backupName(start + n, n));
    await fs.promises.writeFile(path.join(directory, valid[n]), contents);
  }
  const junk = [];
  for (let n = 0; n < 300; n++) {
    // Junk is newer than every valid file, so it would come first if sorted by date alone.
    junk.push(backupName(start + 10000 + n, 5000 + n));
    await fs.promises.writeFile(path.join(directory, junk[n]), 'junk');
  }
  const h = harness(t, vault);

  let result = await h.invoke('vault:list-backups');
  assert.equal(result.success, true);
  assert.equal(result.truncated, true);
  assert.equal(result.items.length, 1000);
  assert.deepEqual(result.items.map((item) => item.id), valid.slice(500).reverse());

  for (const name of valid.slice(0, 1200)) await fs.promises.rm(path.join(directory, name));
  result = await h.invoke('vault:list-backups');
  assert.equal(result.truncated, false);
  assert.equal(result.items.length, 600);
  assert.deepEqual(result.items.slice(0, 300).map((item) => item.status), Array(300).fill('valid'));
  assert.deepEqual(result.items.slice(300).map((item) => item.id), junk.slice().reverse());

  await fs.promises.writeFile(path.join(directory, backupName(start - 1, 9999)), 'junk');
  for (let n = 0; n < 401; n++) {
    await fs.promises.writeFile(path.join(directory, backupName(start + 20000 + n, 7000 + n)), contents);
  }
  result = await h.invoke('vault:list-backups');
  assert.equal(result.truncated, true);
  assert.equal(result.items.length, 1000);
  assert.equal(result.items.filter((item) => item.status === 'valid').length, 701);
  assert.equal(result.items.findIndex((item) => item.status !== 'valid'), 701, 'invalid items only fill the places left');
});

// --- Phase 2A milestone 2A.2: restore preview and restore tokens ---

const OPEN_ERROR = 'Incorrect password, or the backup is damaged.';
const TOKEN_ERROR = 'Preview the backup again before restoring.';
const PASSWORD_ERROR = 'Enter the master password for this backup (1 to 1024 characters).';
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

async function folderBytes(directory) {
  const files = {};
  for (const name of (await fs.promises.readdir(directory)).sort()) {
    files[name] = (await fs.promises.readFile(path.join(directory, name))).toString('base64');
  }
  return files;
}

// A vault with two entries and a backup of it, left locked unless asked otherwise.
async function previewFixture(t, { unlocked = false } = {}) {
  const fixture = await createVault(t);
  await fixture.vault.saveEntry(makeEntry({ site: 'a.example', username: 'alice', password: 'pw-alpha-123', backupCodes: ['code-one'] }));
  await fixture.vault.saveEntry(makeEntry({ site: 'b.example' }));
  const id = await fixture.vault.createBackup();
  if (!unlocked) fixture.vault.lock();
  return { ...fixture, id };
}

const assertTokenGone = (h, token, id) => assert.throws(() => h.ipc.restoreTokens.take(token, id), { message: TOKEN_ERROR });

test('vault:preview-backup works locked, returns metadata and a token, and writes nothing', async (t) => {
  const { vault, vaultPath, directory, id } = await previewFixture(t);
  const h = harness(t, vault);
  const before = await folderBytes(directory);
  const salt = JSON.parse(await fs.promises.readFile(vaultPath, 'utf8')).salt;

  const result = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
  assert.deepEqual(Object.keys(result).sort(), ['success', 'summary', 'token']);
  assert.equal(result.success, true);
  assert.match(result.token, UUID_PATTERN);
  assert.deepEqual(Object.keys(result.summary).sort(), ['entryCount', 'newestUpdatedAt', 'oldestCreatedAt', 'version', 'willUpgrade']);
  assert.equal(result.summary.entryCount, 2);
  assert.equal(result.summary.version, 3);
  assert.equal(result.summary.willUpgrade, false);
  const text = JSON.stringify(result);
  for (const secret of ['a.example', 'alice', 'pw-alpha-123', 'code-one', salt]) {
    assert.equal(text.includes(secret), false, `the response must not contain ${secret}`);
  }
  assert.equal(vault.isUnlocked(), false, 'a preview never unlocks');
  assert.deepEqual(await folderBytes(directory), before, 'vault.json and the backups are byte-identical');

  const record = h.ipc.restoreTokens.take(result.token, id);
  assert.deepEqual(record, {
    id,
    backupDigest: sha256(await fs.promises.readFile(path.join(directory, id))),
    vaultState: sha256(await fs.promises.readFile(vaultPath)),
    unlocked: false,
    createdAt: vault.validateBackupId(id).createdAt,
    summary: result.summary
  });
  assertTokenGone(h, result.token, id);
});

test('vault:preview-backup records an absent vault file', async (t) => {
  const { vault, vaultPath, id } = await previewFixture(t);
  await fs.promises.rm(vaultPath);
  const h = harness(t, vault);
  const { token } = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
  assert.equal(h.ipc.restoreTokens.take(token, id).vaultState, 'absent');
});

test('vault:preview-backup keeps an unlocked session working and counts as activity', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1762900000000 }); // backup names need a 13-digit time
  const { vault, id } = await previewFixture(t);
  const h = harness(t, vault);

  await h.invoke('vault:unlock', MASTER_PASSWORD, MASTER_PASSWORD);
  const key = vault.key;
  t.mock.timers.tick(4 * 60 * 1000);
  const result = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
  assert.equal(result.success, true);
  assert.equal(vault.key, key, 'the session key is the same');
  assert.equal((await h.invoke('vault:load-entries')).entries.length, 2);
  assert.equal(h.ipc.restoreTokens.take(result.token, id).unlocked, true);

  t.mock.timers.tick(4 * 60 * 1000);
  assert.equal(vault.isUnlocked(), true, 'the preview postponed the idle lock');
  t.mock.timers.tick(60 * 1000);
  assert.equal(vault.isUnlocked(), false);
});

test('vault:preview-backup issues a token only on success, and a failed preview drops the outstanding one', async (t) => {
  const { vault, directory, id } = await previewFixture(t);
  const h = harness(t, vault);
  const before = await folderBytes(directory);

  const first = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
  const failed = await h.invoke('vault:preview-backup', id, 'not the right password');
  assert.deepEqual(failed, { success: false, error: OPEN_ERROR });
  assertTokenGone(h, first.token, id);

  const missing = 'vault-backup-1762900000000-0f8e2b7c-1a2b-4c3d-8e9f-a0b1c2d3e4f5.bak';
  const bad = [
    [['../vault.json', MASTER_PASSWORD], 'Invalid backup id.'],
    [['x'.repeat(129), MASTER_PASSWORD], 'Invalid backup id.'],
    [[42, MASTER_PASSWORD], 'Invalid backup id.'],
    [[], 'Invalid backup id.'],
    [[id.replace('.bak', '0.bak'), MASTER_PASSWORD], 'Invalid backup id.'],
    [[id], PASSWORD_ERROR],
    [[id, ''], PASSWORD_ERROR],
    [[id, 'x'.repeat(1025)], PASSWORD_ERROR],
    [[id, { toString: () => MASTER_PASSWORD }], PASSWORD_ERROR],
    [[missing, MASTER_PASSWORD], 'Backup not found.']
  ];
  for (const [args, error] of bad) {
    const outstanding = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
    assert.deepEqual(await h.invoke('vault:preview-backup', ...args), { success: false, error }, JSON.stringify(args));
    assertTokenGone(h, outstanding.token, id);
  }
  assert.deepEqual(await folderBytes(directory), before);
});

test('a second preview replaces the restore token', async (t) => {
  const { vault, id } = await previewFixture(t, { unlocked: true });
  const other = await vault.createBackup();
  vault.lock();
  const h = harness(t, vault);

  // Taking any token uses up the one outstanding, so each check needs its own pair of previews.
  let first = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
  let second = await h.invoke('vault:preview-backup', other, MASTER_PASSWORD);
  assert.notEqual(first.token, second.token);
  assertTokenGone(h, first.token, id);

  first = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
  second = await h.invoke('vault:preview-backup', other, MASTER_PASSWORD);
  assert.equal(h.ipc.restoreTokens.take(second.token, other).id, other);
});

test('a restore token works once, only for its backup, and a wrong one also uses it up', async (t) => {
  const { vault, id } = await previewFixture(t);
  const h = harness(t, vault);
  const other = id.replace(/-\d{13}-/, '-1762900000000-');

  for (const [token, forId] of [[undefined, id], [42, id], ['not-the-token', id], [null, id], ['REAL', other]]) {
    const { token: real } = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
    assert.throws(() => h.ipc.restoreTokens.take(token === 'REAL' ? real : token, forId), { message: TOKEN_ERROR });
    assertTokenGone(h, real, id);
  }
  assert.throws(() => h.ipc.restoreTokens.take(undefined, undefined), { message: TOKEN_ERROR }, 'no token outstanding');
});

test('a restore token expires after 2 minutes, by its timer or by the clock', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1762900000000 });
  const { vault, id } = await previewFixture(t);
  const h = harness(t, vault);
  assert.equal(DEFAULTS.restoreTokenMs, 2 * 60 * 1000);

  let { token } = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
  t.mock.timers.tick(DEFAULTS.restoreTokenMs - 1);
  assert.equal(h.ipc.restoreTokens.take(token, id).id, id, 'still valid just before expiry');

  ({ token } = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD));
  t.mock.timers.tick(DEFAULTS.restoreTokenMs);
  assertTokenGone(h, token, id);

  // A suspended computer: the clock jumps without the timer firing.
  ({ token } = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD));
  t.mock.timers.setTime(Date.now() + DEFAULTS.restoreTokenMs);
  assertTokenGone(h, token, id);
});

test('lock, auto-lock, unlock, a password change, a CSV import and shutDown cancel the restore token', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: 1762900000000 });
  const { vault, directory, id } = await previewFixture(t);
  const h = harness(t, vault);
  const csvPath = path.join(directory, 'passwords.csv');
  await fs.promises.writeFile(csvPath, 'name,url,username,password\nNew,https://new.example,bob,Sup3r-Secret!\n');
  const picks = [null, csvPath];
  registerCsvHandlers({
    registerVaultHandler: h.ipc.registerVaultHandler,
    getVault: () => vault,
    getParentWindow: () => null,
    dialog: {
      showOpenDialog: async () => {
        const pick = picks.shift();
        return pick ? { canceled: false, filePaths: [pick] } : { canceled: true, filePaths: [] };
      },
      showMessageBox: async () => ({ response: 1 }) // import and keep the CSV file
    },
    getDefaultDirectory: () => directory,
    onActivity: h.ipc.armIdleLock
  });
  const preview = async () => {
    const result = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
    assert.equal(result.success, true);
    return result.token;
  };
  const unlockAndPreview = async () => {
    assert.equal((await h.invoke('vault:unlock', MASTER_PASSWORD)).success, true);
    return preview();
  };
  const NEW_PASSWORD = 'a brand new master password';
  // Each action returns the token it must cancel; the ones that need an unlocked vault unlock first.
  const cancels = {
    'lock': async (token) => {
      assert.equal((await h.invoke('vault:lock')).success, true);
      return token;
    },
    'unlock': async (token) => {
      assert.equal((await h.invoke('vault:unlock', MASTER_PASSWORD)).success, true);
      return token;
    },
    'failed unlock': async (token) => {
      assert.equal((await h.invoke('vault:unlock', 'wrong password!')).success, false);
      return token;
    },
    'auto-lock': async () => {
      // The idle lock (5 minutes) must fire while the token (2 minutes) is still valid, and a
      // preview counts as activity, so issue this token through the store just before it fires.
      assert.equal((await h.invoke('vault:unlock', MASTER_PASSWORD)).success, true);
      t.mock.timers.tick(DEFAULTS.idleLockMs - 1);
      const token = h.ipc.restoreTokens.issue({ id, backupDigest: 'digest', vaultState: 'absent', unlocked: true, createdAt: 0, summary: {} });
      t.mock.timers.tick(1);
      assert.equal(vault.isUnlocked(), false);
      return token;
    },
    'password change': async () => {
      const token = await unlockAndPreview();
      assert.equal((await h.invoke('vault:change-master-password', MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD)).success, true);
      // Put the old password back without a token outstanding, so later steps work the same way.
      assert.equal((await h.invoke('vault:change-master-password', NEW_PASSWORD, MASTER_PASSWORD, MASTER_PASSWORD)).success, true);
      return token;
    },
    'CSV import cancelled at the file picker': async () => {
      const token = await unlockAndPreview();
      assert.deepEqual(await h.invoke('vault:import-csv'), { success: false, cancelled: true });
      return token;
    },
    'CSV import': async () => {
      const token = await unlockAndPreview();
      const result = await h.invoke('vault:import-csv');
      assert.equal(result.success, true);
      assert.equal(result.added, 1);
      return token;
    },
    'shutDown': async (token) => {
      h.ipc.shutDown();
      return token;
    }
  };

  for (const [label, action] of Object.entries(cancels)) {
    const token = await action(await preview());
    assert.throws(() => h.ipc.restoreTokens.take(token, id), { message: TOKEN_ERROR }, label);
  }
});

test('every restore-token cancel event increases the cancel count', async (t) => {
  const { vault, id } = await previewFixture(t);
  const h = harness(t, vault);
  let count = h.ipc.restoreTokens.cancelCount;
  const bumped = () => {
    const next = h.ipc.restoreTokens.cancelCount;
    assert.ok(next > count);
    count = next;
  };
  await h.invoke('vault:lock');
  bumped();
  await h.invoke('vault:unlock', MASTER_PASSWORD);
  bumped();
  h.ipc.lockIfIdle(); // not idle yet: no lock, no cancel
  assert.equal(h.ipc.restoreTokens.cancelCount, count);
  await h.invoke('vault:preview-backup', id, 'wrong password!');
  bumped();
  h.ipc.restoreTokens.cancel();
  bumped();
  h.ipc.shutDown();
  bumped();
});

test('vault:preview-backup rejects callers that are not the app page, and leaves the token alone', async (t) => {
  const { vault, directory, id } = await previewFixture(t);
  const h = harness(t, vault);
  const { token } = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
  const before = await folderBytes(directory);
  const countBefore = h.ipc.restoreTokens.cancelCount;

  const subframe = { senderFrame: { url: PAGE_URL }, sender: h.contents };
  const website = { senderFrame: { url: 'https://example.com/' }, sender: { mainFrame: null } };
  website.sender.mainFrame = website.senderFrame;
  for (const event of [subframe, website, {}]) {
    assert.deepEqual(await h.invokeAs(event, 'vault:preview-backup', id, MASTER_PASSWORD), { success: false, error: 'Unauthorized caller.' });
  }
  assert.equal(h.ipc.restoreTokens.cancelCount, countBefore);
  assert.deepEqual(await folderBytes(directory), before);
  assert.equal(h.ipc.restoreTokens.take(token, id).id, id, 'the token from the trusted preview still works');
});

// --- Phase 2A milestone 2A.3: restore (the full cases are in vault-backup-restore.test.js) ---

test('vault:restore-backup rejects callers that are not the app page, and leaves the token and files alone', async (t) => {
  const { vault, directory, id } = await previewFixture(t, { unlocked: true });
  await vault.saveEntry(makeEntry({ site: 'c.example' })); // so the backup differs from the vault
  const h = harness(t, vault);
  const { token } = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
  const before = await folderBytes(directory);
  const countBefore = h.ipc.restoreTokens.cancelCount;

  const subframe = { senderFrame: { url: PAGE_URL }, sender: h.contents };
  const website = { senderFrame: { url: 'https://example.com/' }, sender: { mainFrame: null } };
  website.sender.mainFrame = website.senderFrame;
  for (const event of [subframe, website, {}]) {
    assert.deepEqual(await h.invokeAs(event, 'vault:restore-backup', id, token), { success: false, error: 'Unauthorized caller.' });
  }
  assert.equal(h.dialogs.length, 0, 'no confirmation opens for an untrusted caller');
  assert.equal(h.ipc.restoreTokens.cancelCount, countBefore);
  assert.deepEqual(await folderBytes(directory), before);
  assert.equal(vault.isUnlocked(), true);

  const result = await h.invoke('vault:restore-backup', id, token);
  assert.equal(result.success, true, 'the token from the trusted preview still works');
  assert.equal(result.restoredFrom, id);
  assert.equal(h.dialogs.length, 1);
  assert.equal(vault.isUnlocked(), false);
});

test('vault:restore-backup checks its arguments and returns errors without paths', async (t) => {
  const { vault, directory, id } = await previewFixture(t);
  const h = harness(t, vault);
  const before = await folderBytes(directory);
  for (const [args, error] of [
    [[], 'Invalid backup id.'],
    [[42, 'token'], 'Invalid backup id.'],
    [['..\vault.json', 'token'], 'Invalid backup id.'],
    [[id], TOKEN_ERROR],
    [[id, 42], TOKEN_ERROR],
    [[id, ['token']], TOKEN_ERROR]
  ]) {
    const { token } = await h.invoke('vault:preview-backup', id, MASTER_PASSWORD);
    const result = await h.invoke('vault:restore-backup', ...args);
    assert.deepEqual(result, { success: false, error }, JSON.stringify(args));
    assert.equal(result.error.includes(directory), false);
    assertTokenGone(h, token, id);
  }
  assert.equal(h.dialogs.length, 0);
  assert.deepEqual(await folderBytes(directory), before);
});
