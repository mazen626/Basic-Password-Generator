// Phase 2A milestone 2A.3: transactional restore (docs/PHASE-2A-DESIGN.md, part D). Every case runs
// in a temporary folder. Each failure must leave vault.json byte-identical and the key and lock
// state as they were.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const PasswordVault = require('../vault');
const { registerCsvHandlers } = require('../csv-transfer');
const { createIpcHandlers, DEFAULTS } = require('../ipc-handlers');
const { MASTER_PASSWORD, createVault, makeEntry } = require('./helpers');

const PAGE_URL = 'file:///C:/app/page.html';
const BACKUP_PASSWORD = 'an older backup password';
const UUID = '0f8e2b7c-1a2b-4c3d-8e9f-a0b1c2d3e4f5';
const MS = 1762900000000;
const MAX_VAULT_BYTES = 8 * 1024 * 1024;
const TOKEN_ERROR = 'Preview the backup again before restoring.';
const CHANGED_ERROR = 'The vault changed while the confirmation was open. Preview the backup again.';
const VAULT_CHANGED = 'The vault changed after the preview. Preview the backup again.';
const BACKUP_CHANGED = 'The backup changed after the preview. Preview the backup again.';
const SAME_ERROR = 'This backup is the same as the current vault.';
const PRE_RESTORE_ERROR = 'Could not save a copy of the current vault, so nothing was restored.';
const WRITE_ERROR = 'Could not write the restored vault. The current vault was not changed.';
const PRE_RESTORE_NAME = /^vault-before-restore-\d{13}-[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\.bak$/;

const backupId = (ms = MS) => `vault-backup-${ms}-${UUID}.bak`;
const legacyId = (version, ms = MS) => `vault.json.v${version}-${ms}-${UUID}.bak`;
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

// An envelope of any version holding exactly `entries`, encrypted with `password`, at the lowest
// iteration count the vault accepts so the tests stay fast.
function makeEnvelope(entries, { version = 3, password = BACKUP_PASSWORD } = {}) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(entries), 'utf8'), cipher.final()]);
  key.fill(0);
  return Buffer.from(JSON.stringify({
    version,
    kdf: 'pbkdf2-sha256',
    iterations: 100000,
    cipher: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  }, null, 2));
}

function storedEntry(overrides = {}) {
  return {
    id: crypto.randomUUID(),
    site: 'example.com',
    username: 'alice',
    password: 'secret-password',
    notes: '',
    category: 'login',
    favorite: false,
    backupCodes: [{ id: crypto.randomUUID(), code: 'code-one', used: false }],
    createdAt: '2025-01-01T00:00:00.000Z',
    updatedAt: '2025-01-01T00:00:00.000Z',
    ...overrides
  };
}

// Every file in the folder, name -> base64 bytes.
async function snapshot(directory) {
  const files = {};
  for (const name of (await fs.readdir(directory)).sort()) {
    files[name] = (await fs.readFile(path.join(directory, name))).toString('base64');
  }
  return files;
}

// The folder plus the key object and its bytes, to prove a failure changed nothing.
async function capture(vault, directory) {
  return { files: await snapshot(directory), key: vault.key, keyBytes: vault.key ? Buffer.from(vault.key) : null };
}

async function assertUnchanged(vault, directory, before, label) {
  assert.deepEqual(await snapshot(directory), before.files, `${label}: the folder must be byte-identical`);
  assertKeyUnchanged(vault, before, label);
}

function assertKeyUnchanged(vault, before, label) {
  assert.equal(vault.key, before.key, `${label}: the same key (or none) stays in use`);
  assert.deepEqual(vault.key ? Buffer.from(vault.key) : null, before.keyBytes, `${label}: the key bytes are unchanged`);
}

// The real handlers around fake Electron objects. Set `h.answer` for the button pressed and
// `h.onDialog` to run something while the confirmation is open.
function harness(t, vault) {
  const handlers = new Map();
  const dialogs = [];
  const win = { isDestroyed: () => false, webContents: { send: () => {} } };
  const h = { answer: 0, onDialog: null, dialogs, win };
  const ipc = createIpcHandlers({
    ipcMain: { handle: (channel, handler) => handlers.set(channel, handler) },
    getVault: () => vault,
    pageUrl: PAGE_URL,
    clipboard: { readText: () => '', writeText: () => {}, clear: () => {} },
    dialog: {
      showMessageBox: async (parent, options) => {
        dialogs.push({ parent, options });
        if (h.onDialog) await h.onDialog();
        return { response: h.answer };
      }
    },
    shell: { openPath: async () => '' },
    getFocusedWindow: () => win,
    getAllWindows: () => [win],
    getWindowFor: () => win,
    quit: () => {}
  });
  ipc.registerAll();
  t.after(() => ipc.shutDown());
  const frame = { url: PAGE_URL };
  const trusted = { senderFrame: frame, sender: { mainFrame: frame } };
  h.ipc = ipc;
  h.invoke = (channel, ...args) => handlers.get(channel)(trusted, ...args);
  h.invokeAs = (event, channel, ...args) => handlers.get(channel)(event, ...args);
  h.preview = async (id, password = BACKUP_PASSWORD) => {
    const result = await h.invoke('vault:preview-backup', id, password);
    assert.equal(result.success, true, result.error);
    return result.token;
  };
  h.restore = (id, token) => h.invoke('vault:restore-backup', id, token);
  return h;
}

// A vault (master password MASTER_PASSWORD, one entry) and a three-entry backup made with
// BACKUP_PASSWORD, so a restore visibly changes both the entries and the password.
async function fixture(t, { unlocked = true } = {}) {
  const made = await createVault(t);
  await made.vault.saveEntry(makeEntry({ site: 'current.example' }));
  const entries = ['a.example', 'b.example', 'c.example'].map((site) => storedEntry({ site }));
  const backupBytes = makeEnvelope(entries);
  const id = backupId();
  await fs.writeFile(path.join(made.directory, id), backupBytes);
  if (!unlocked) made.vault.lock();
  return { ...made, id, entries, backupBytes };
}

// Wraps fs.open so files whose name passes `match`, opened with `flag`, get faulty handle steps.
function breakOpen(t, match, flag, steps) {
  const realOpen = fs.open;
  t.mock.method(fs, 'open', async (filePath, openFlag, ...rest) => {
    if (match(path.basename(String(filePath))) && openFlag === flag) {
      if (steps.open) throw steps.open();
      const handle = await realOpen(filePath, openFlag, ...rest);
      for (const [step, replace] of Object.entries(steps)) {
        if (step === 'open') continue;
        const real = handle[step].bind(handle);
        handle[step] = (...args) => replace(real, ...args);
      }
      return handle;
    }
    return realOpen(filePath, openFlag, ...rest);
  });
}

const isPreRestore = (name) => name.startsWith('vault-before-restore-');
const isTemp = (name) => name === 'vault.json.tmp';

test('a restore replaces vault.json with the backup bytes, saves the old vault first and locks', async (t) => {
  const { vault, vaultPath, directory, id, entries, backupBytes } = await fixture(t);
  const h = harness(t, vault);
  const oldBytes = await fs.readFile(vaultPath);
  const oldKey = vault.key;
  const token = await h.preview(id);

  const result = await h.restore(id, token);
  assert.deepEqual(Object.keys(result).sort(), ['preRestoreBackup', 'restoredFrom', 'success']);
  assert.equal(result.success, true);
  assert.equal(result.restoredFrom, id);
  assert.match(result.preRestoreBackup, PRE_RESTORE_NAME);

  assert.deepEqual(await fs.readFile(vaultPath), backupBytes, 'vault.json is the backup, byte for byte');
  assert.deepEqual(await fs.readFile(path.join(directory, result.preRestoreBackup)), oldBytes, 'the pre-restore copy is the old vault');
  assert.deepEqual(await fs.readFile(path.join(directory, id)), backupBytes, 'the backup itself is untouched');
  assert.deepEqual((await fs.readdir(directory)).sort(), [id, result.preRestoreBackup, 'vault.json'].sort(), 'no .tmp is left');
  assert.equal(vault.isUnlocked(), false, 'the vault is locked');
  assert.ok(oldKey.every((byte) => byte === 0), 'the old key is zeroed');

  // The pre-restore copy is listed as a valid pre-restore backup.
  const listed = (await vault.listBackups()).find((item) => item.id === result.preRestoreBackup);
  assert.equal(listed.kind, 'pre-restore');
  assert.equal(listed.status, 'valid');

  await assert.rejects(vault.unlock(MASTER_PASSWORD), /Incorrect master password/);
  assert.equal((await vault.unlock(BACKUP_PASSWORD)).migrated, false);
  assert.deepEqual(await vault.loadEntries(), entries, 'the entries verify');
  assert.deepEqual(await fs.readFile(vaultPath), backupBytes, 'unlocking a version 3 vault does not rewrite it');

  assert.deepEqual(await h.restore(id, token), { success: false, error: TOKEN_ERROR }, 'the token is used up');
  assert.equal(h.dialogs.length, 1, 'a used token opens no second dialog');
});

test('the confirmation is native, defaults to Cancel and is built from the token record', async (t) => {
  const { vault, id } = await fixture(t);
  const h = harness(t, vault);
  h.answer = 1;
  await h.restore(id, await h.preview(id));

  assert.equal(h.dialogs.length, 1);
  const { parent, options } = h.dialogs[0];
  assert.equal(parent, h.win, 'the app window is the parent');
  assert.equal(options.buttons[options.defaultId], 'Cancel');
  assert.equal(options.buttons[options.cancelId], 'Cancel');
  const date = new Date(MS);
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const pad = (value) => String(value).padStart(2, '0');
  const when = `${date.getDate()} ${months[date.getMonth()]} ${date.getFullYear()}, ${pad(date.getHours())}:${pad(date.getMinutes())}`;
  assert.equal(options.message, `Replace the current vault with the backup from ${when} (3 entries)?`);
  assert.match(options.detail, /^Kind: Backup\./);
  assert.match(options.detail, /The current vault is saved first/);
  assert.match(options.detail, /Changes made after this backup was created will be replaced/);
  for (const text of [options.message, options.detail]) {
    assert.equal(text.includes('a.example'), false, 'no entry data in the dialog');
    assert.equal(text.includes(path.sep), false, 'no path in the dialog');
  }
});

test('cancelling the confirmation changes nothing and uses the token up', async (t) => {
  const { vault, directory, id } = await fixture(t);
  const h = harness(t, vault);
  const token = await h.preview(id);
  const before = await capture(vault, directory);
  h.answer = 1;

  assert.deepEqual(await h.restore(id, token), { success: false, cancelled: true });
  await assertUnchanged(vault, directory, before, 'cancel');
  assert.equal(vault.isUnlocked(), true);
  h.answer = 0;
  assert.deepEqual(await h.restore(id, token), { success: false, error: TOKEN_ERROR });
  assert.equal(h.dialogs.length, 1);
});

test('missing, wrong, reused and mismatched tokens are refused without a dialog, and use the token up', async (t) => {
  const { vault, directory, id, backupBytes } = await fixture(t);
  const other = backupId(MS + 1);
  await fs.writeFile(path.join(directory, other), backupBytes);
  const h = harness(t, vault);
  const before = await capture(vault, directory);

  const cases = [
    ['missing', (token) => [id, undefined, token]],
    ['not a string', (token) => [id, 42, token]],
    ['object', (token) => [id, { toString: () => token }, token]],
    ['wrong', (token) => [id, crypto.randomUUID(), token]],
    ['for another backup', (token) => [other, token, token]],
    ['invalid id', (token) => ['../vault.json', token, token]]
  ];
  for (const [label, make] of cases) {
    const real = await h.preview(id);
    const [forId, sent] = make(real);
    const expected = forId === '../vault.json' ? 'Invalid backup id.' : TOKEN_ERROR;
    assert.deepEqual(await h.restore(forId, sent), { success: false, error: expected }, label);
    assert.deepEqual(await h.restore(id, real), { success: false, error: TOKEN_ERROR }, `${label}: the real token is gone`);
  }
  assert.deepEqual(await h.restore(id, crypto.randomUUID()), { success: false, error: TOKEN_ERROR }, 'no token outstanding');
  assert.equal(h.dialogs.length, 0);
  await assertUnchanged(vault, directory, before, 'bad tokens');
});

test('an expired token is refused', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: MS });
  const { vault, directory, id } = await fixture(t, { unlocked: false });
  const h = harness(t, vault);

  let token = await h.preview(id);
  t.mock.timers.tick(DEFAULTS.restoreTokenMs);
  const before = await capture(vault, directory);
  assert.deepEqual(await h.restore(id, token), { success: false, error: TOKEN_ERROR }, 'by its timer');

  token = await h.preview(id);
  t.mock.timers.setTime(Date.now() + DEFAULTS.restoreTokenMs);
  assert.deepEqual(await h.restore(id, token), { success: false, error: TOKEN_ERROR }, 'by the clock');
  assert.equal(h.dialogs.length, 0);
  await assertUnchanged(vault, directory, before, 'expired');
});

test('a backup changed, replaced or removed after the preview is refused', async (t) => {
  const { vault, directory, id, entries } = await fixture(t);
  const h = harness(t, vault);
  const changes = {
    'another valid backup': [() => fs.writeFile(path.join(directory, id), makeEnvelope(entries)), BACKUP_CHANGED],
    'one byte appended': [async () => fs.appendFile(path.join(directory, id), ' '), BACKUP_CHANGED],
    'invalid contents': [() => fs.writeFile(path.join(directory, id), 'not json'), 'Backup file is invalid or corrupted.'],
    'removed': [() => fs.rm(path.join(directory, id)), 'Backup not found.']
  };
  for (const [label, [change, error]] of Object.entries(changes)) {
    await fs.writeFile(path.join(directory, id), makeEnvelope(entries));
    const token = await h.preview(id);
    await change();
    const before = await capture(vault, directory);
    assert.deepEqual(await h.restore(id, token), { success: false, error }, label);
    await assertUnchanged(vault, directory, before, label);
    assert.equal(vault.isUnlocked(), true);
  }
});

test('a vault file changed, removed or created after the preview is refused', async (t) => {
  const { vault, vaultPath, directory, id } = await fixture(t);
  const h = harness(t, vault);

  let token = await h.preview(id);
  await vault.saveEntry(makeEntry({ site: 'saved-after-preview.example' }));
  let before = await capture(vault, directory);
  assert.deepEqual(await h.restore(id, token), { success: false, error: VAULT_CHANGED }, 'an entry saved');
  await assertUnchanged(vault, directory, before, 'an entry saved');
  assert.equal((await vault.loadEntries()).length, 2, 'the session keeps working');

  const saved = await fs.readFile(vaultPath);
  token = await h.preview(id);
  await fs.rm(vaultPath);
  before = await capture(vault, directory);
  assert.deepEqual(await h.restore(id, token), { success: false, error: VAULT_CHANGED }, 'vault.json removed');
  await assertUnchanged(vault, directory, before, 'vault.json removed');

  token = await h.preview(id);
  await fs.writeFile(vaultPath, saved);
  before = await capture(vault, directory);
  assert.deepEqual(await h.restore(id, token), { success: false, error: VAULT_CHANGED }, 'vault.json created');
  await assertUnchanged(vault, directory, before, 'vault.json created');
});

test('a backup identical to the current vault is refused', async (t) => {
  const { vault, directory } = await fixture(t);
  const same = await vault.createBackup();
  const h = harness(t, vault);
  const token = await h.preview(same, MASTER_PASSWORD);
  const before = await capture(vault, directory);

  assert.deepEqual(await h.restore(same, token), { success: false, error: SAME_ERROR });
  await assertUnchanged(vault, directory, before, 'identical');
  assert.equal(vault.isUnlocked(), true);
});

test('auto-lock firing while the confirmation is open stops the restore', async (t) => {
  t.mock.timers.enable({ apis: ['setTimeout', 'Date'], now: MS });
  const { vault, directory, id } = await fixture(t);
  const h = harness(t, vault);
  const token = await h.preview(id); // arms the idle lock
  const before = await capture(vault, directory);
  h.onDialog = () => t.mock.timers.tick(DEFAULTS.idleLockMs);

  assert.deepEqual(await h.restore(id, token), { success: false, error: CHANGED_ERROR });
  assert.equal(vault.isUnlocked(), false, 'the auto-lock itself happened');
  assert.deepEqual(await snapshot(directory), before.files, 'nothing was written');
  h.onDialog = null;
  assert.deepEqual(await h.restore(id, token), { success: false, error: TOKEN_ERROR }, 'the token is gone');
});

test('a cancel event or a lock-state change while the confirmation is open stops the restore', async (t) => {
  const { vault, directory, id } = await fixture(t);
  const h = harness(t, vault);
  const events = {
    'a cancel event (count only)': { unlocked: true, during: () => h.ipc.restoreTokens.cancel(), after: true },
    'the vault locked': { unlocked: true, during: () => vault.lock(), after: false },
    'shutDown': { unlocked: true, during: () => h.ipc.shutDown(), after: false },
    'the vault unlocked': { unlocked: false, during: () => vault.unlock(MASTER_PASSWORD), after: true }
  };
  for (const [label, { unlocked, during, after }] of Object.entries(events)) {
    if (unlocked && !vault.isUnlocked()) await vault.unlock(MASTER_PASSWORD);
    if (!unlocked) vault.lock();
    const token = await h.preview(id);
    const before = await snapshot(directory);
    h.onDialog = during;
    assert.deepEqual(await h.restore(id, token), { success: false, error: CHANGED_ERROR }, label);
    h.onDialog = null;
    assert.deepEqual(await snapshot(directory), before, `${label}: nothing was written`);
    assert.equal(vault.isUnlocked(), after, `${label}: only the event itself changed the lock state`);
  }
});

test('a password change, a CSV import and a failed restore cancel the restore token', async (t) => {
  const { vault, directory, id } = await fixture(t);
  const h = harness(t, vault);
  const csvPath = path.join(directory, 'passwords.csv');
  registerCsvHandlers({
    registerVaultHandler: h.ipc.registerVaultHandler,
    getVault: () => vault,
    getParentWindow: () => null,
    dialog: {
      showOpenDialog: async () => {
        await fs.writeFile(csvPath, `name,url,username,password\nNew,https://n${crypto.randomUUID()}.example,bob,Sup3r-Secret!\n`);
        return { canceled: false, filePaths: [csvPath] };
      },
      showMessageBox: async () => ({ response: 0 }) // import and delete the CSV file
    },
    getDefaultDirectory: () => directory,
    onActivity: h.ipc.armIdleLock
  });
  const NEW_PASSWORD = 'a brand new master password';
  const cancels = {
    'password change': async () => {
      assert.equal((await h.invoke('vault:change-master-password', MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD)).success, true);
      assert.equal((await h.invoke('vault:change-master-password', NEW_PASSWORD, MASTER_PASSWORD, MASTER_PASSWORD)).success, true);
    },
    'CSV import': async () => assert.equal((await h.invoke('vault:import-csv')).success, true),
    'failed restore': async () => assert.equal((await h.restore(id, 'not the token')).success, false)
  };
  for (const [label, action] of Object.entries(cancels)) {
    const token = await h.preview(id);
    await action();
    const before = await capture(vault, directory);
    assert.deepEqual(await h.restore(id, token), { success: false, error: TOKEN_ERROR }, label);
    await assertUnchanged(vault, directory, before, label);
  }
  assert.equal(h.dialogs.length, 0);
});

test('a write queued while the confirmation is open runs after the restore, against the locked vault', async (t) => {
  const { vault, vaultPath, id, backupBytes } = await fixture(t);
  const h = harness(t, vault);
  const token = await h.preview(id);
  let queued;
  h.onDialog = () => { queued = h.invoke('vault:save-entry', makeEntry({ site: 'queued.example' })); };

  assert.equal((await h.restore(id, token)).success, true);
  assert.deepEqual(await queued, { success: false, error: 'Unlock the vault first.' });
  assert.deepEqual(await fs.readFile(vaultPath), backupBytes);
});

test('if the pre-restore copy cannot be written, nothing is restored', async (t) => {
  const failures = {
    'open': { open: () => Object.assign(new Error('EACCES: permission denied'), { code: 'EACCES' }) },
    'writeFile': { writeFile: async () => { throw new Error('writeFile failed'); } },
    'sync': { sync: async () => { throw new Error('sync failed'); } },
    'disk full mid-write': {
      writeFile: async (real, contents) => {
        await real(contents.subarray(0, 10));
        throw Object.assign(new Error('ENOSPC: no space left on device'), { code: 'ENOSPC' });
      }
    }
  };
  for (const [label, steps] of Object.entries(failures)) {
    await t.test(label, async (st) => {
      const { vault, directory, id } = await fixture(st);
      const h = harness(st, vault);
      const token = await h.preview(id);
      const before = await capture(vault, directory);
      breakOpen(st, isPreRestore, 'wx', steps);
      const renames = st.mock.method(fs, 'rename');

      const result = await h.restore(id, token);
      assert.deepEqual(result, { success: false, error: PRE_RESTORE_ERROR });
      assert.equal(renames.mock.callCount(), 0, 'vault.json is never replaced');
      st.mock.restoreAll();
      await assertUnchanged(vault, directory, before, label);
      assert.equal(vault.isUnlocked(), true);
      assert.deepEqual(await h.restore(id, token), { success: false, error: TOKEN_ERROR });
    });
  }
});

test('if the pre-restore copy does not match what was read, nothing is restored', async (t) => {
  const { vault, directory, id } = await fixture(t);
  const h = harness(t, vault);
  const token = await h.preview(id);
  const before = await capture(vault, directory);
  breakOpen(t, isPreRestore, 'wx', {
    writeFile: (real, contents) => real(Buffer.concat([contents, Buffer.from(' ')]))
  });
  const renames = t.mock.method(fs, 'rename');

  assert.deepEqual(await h.restore(id, token), { success: false, error: PRE_RESTORE_ERROR });
  assert.equal(renames.mock.callCount(), 0);
  t.mock.restoreAll();
  await assertUnchanged(vault, directory, before, 'digest mismatch');
});

test('the restored file is written to .tmp and flushed before the rename', async (t) => {
  const { vault, id } = await fixture(t);
  const h = harness(t, vault);
  const token = await h.preview(id);
  const events = [];
  breakOpen(t, isTemp, 'w', Object.fromEntries(['writeFile', 'sync', 'close'].map((step) => [
    step, (real, ...args) => { events.push(step); return real(...args); }
  ])));
  const realRename = fs.rename;
  t.mock.method(fs, 'rename', async (...args) => { events.push('rename'); return realRename(...args); });

  assert.equal((await h.restore(id, token)).success, true);
  assert.deepEqual(events, ['writeFile', 'sync', 'close', 'rename']);
});

test('if writing the restored file fails or stops before the rename, vault.json and the pre-restore copy are kept', async (t) => {
  const failures = {
    'temp writeFile': (st) => breakOpen(st, isTemp, 'w', { writeFile: async () => { throw new Error('writeFile failed'); } }),
    'temp sync': (st) => breakOpen(st, isTemp, 'w', { sync: async () => { throw new Error('sync failed'); } }),
    'interrupted before the rename': (st) => st.mock.method(fs, 'rename', async () => {
      throw Object.assign(new Error('EPERM: operation not permitted, rename'), { code: 'EPERM' });
    })
  };
  for (const [label, inject] of Object.entries(failures)) {
    await t.test(label, async (st) => {
      const { vault, vaultPath, directory, id } = await fixture(st);
      const h = harness(st, vault);
      const oldBytes = await fs.readFile(vaultPath);
      const token = await h.preview(id);
      const before = await capture(vault, directory);
      inject(st);

      const result = await h.restore(id, token);
      st.mock.restoreAll();
      assert.deepEqual(result, { success: false, error: WRITE_ERROR }, label);
      assert.equal(result.error.includes(directory), false, 'no path in the message');
      assert.deepEqual(await fs.readFile(vaultPath), oldBytes, 'vault.json is byte-identical');
      assertKeyUnchanged(vault, before, label);
      assert.equal(vault.isUnlocked(), true, 'the vault stays unlocked');

      const added = (await fs.readdir(directory)).filter((name) => !Object.hasOwn(before.files, name));
      assert.equal(added.length, 1, 'only the pre-restore copy was added; the .tmp is gone');
      assert.match(added[0], PRE_RESTORE_NAME);
      assert.deepEqual(await fs.readFile(path.join(directory, added[0])), oldBytes);

      assert.deepEqual(await h.restore(id, token), { success: false, error: TOKEN_ERROR });
      await vault.saveEntry(makeEntry({ site: 'after-failure.example' }));
      assert.equal((await vault.loadEntries()).length, 2, 'later saves still work');
    });
  }
});

test('a restore with no vault.json writes no pre-restore copy', async (t) => {
  const { vault, vaultPath, directory, id, entries, backupBytes } = await fixture(t, { unlocked: false });
  await fs.rm(vaultPath);
  const h = harness(t, vault);
  const token = await h.preview(id);

  const result = await h.restore(id, token);
  assert.deepEqual(result, { success: true, restoredFrom: id, preRestoreBackup: null });
  assert.match(h.dialogs[0].options.detail, /There is no current vault file, so there is nothing to save first/);
  assert.deepEqual(await fs.readFile(vaultPath), backupBytes);
  assert.deepEqual((await fs.readdir(directory)).sort(), [id, 'vault.json'].sort());
  await vault.unlock(BACKUP_PASSWORD);
  assert.deepEqual(await vault.loadEntries(), entries);
});

test('a vault with damaged ciphertext is restored while locked', async (t) => {
  const { vault, vaultPath, directory, id, entries, backupBytes } = await fixture(t, { unlocked: false });
  const envelope = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  ciphertext[0] ^= 1;
  const damaged = Buffer.from(JSON.stringify({ ...envelope, ciphertext: ciphertext.toString('base64') }, null, 2));
  await fs.writeFile(vaultPath, damaged);
  await assert.rejects(vault.unlock(MASTER_PASSWORD), /Incorrect master password or vault data is corrupted/);
  const h = harness(t, vault);

  const result = await h.restore(id, await h.preview(id));
  assert.equal(result.success, true);
  assert.deepEqual(await fs.readFile(vaultPath), backupBytes);
  assert.deepEqual(await fs.readFile(path.join(directory, result.preRestoreBackup)), damaged, 'the damaged vault is kept');
  await vault.unlock(BACKUP_PASSWORD);
  assert.deepEqual(await vault.loadEntries(), entries);
});

test('legacy version 1 and 2 backups are restored byte for byte and upgraded on the next unlock', async (t) => {
  const legacy = {
    1: [{ site: 'Old', password: 'old-secret' }, { site: 'Dated', password: 'pw', username: 'bob', createdAt: '2020-02-02T00:00:00.000Z', updatedAt: '2020-03-03T00:00:00.000Z' }],
    2: ['a.example', 'b.example'].map((site) => {
      const { backupCodes: _codes, ...entry } = storedEntry({ site });
      return entry;
    })
  };
  for (const version of [1, 2]) {
    await t.test(`version ${version}`, async (st) => {
      const { vault, vaultPath, directory } = await fixture(st, { unlocked: false });
      const bytes = makeEnvelope(legacy[version], { version });
      const id = legacyId(version);
      await fs.writeFile(path.join(directory, id), bytes);
      const h = harness(st, vault);

      assert.equal((await h.restore(id, await h.preview(id))).success, true);
      assert.deepEqual(await fs.readFile(vaultPath), bytes, 'restored exactly, still the old version');
      assert.match(h.dialogs[0].options.detail, /^Kind: Pre-upgrade backup\./);

      const namesBefore = await fs.readdir(directory);
      assert.equal((await vault.unlock(BACKUP_PASSWORD)).migrated, true);
      assert.equal(JSON.parse(await fs.readFile(vaultPath, 'utf8')).version, 3);
      const upgradeCopy = (await fs.readdir(directory)).find((name) => !namesBefore.includes(name));
      assert.match(upgradeCopy, new RegExp(`^vault\\.json\\.v${version}-\\d{13}-`));
      assert.deepEqual(await fs.readFile(path.join(directory, upgradeCopy)), bytes, 'the upgrade made its own copy');
      const sites = (await vault.loadEntries()).map((entry) => entry.site).sort();
      assert.deepEqual(sites, legacy[version].map((entry) => entry.site).sort());
    });
  }
});

test('an oversized vault.json is copied with copyFile and checked before the restore', async (t) => {
  const { vault, vaultPath, directory, id, backupBytes } = await fixture(t, { unlocked: false });
  const huge = Buffer.alloc(MAX_VAULT_BYTES + 1024, 0x61);
  await fs.writeFile(vaultPath, huge);
  const h = harness(t, vault);

  const copies = t.mock.method(fs, 'copyFile');
  const result = await h.restore(id, await h.preview(id));
  assert.equal(result.success, true);
  assert.equal(copies.mock.callCount(), 1);
  assert.equal(copies.mock.calls[0].arguments[2], fs.constants.COPYFILE_EXCL);
  assert.equal(sha256(await fs.readFile(path.join(directory, result.preRestoreBackup))), sha256(huge));
  assert.deepEqual(await fs.readFile(vaultPath), backupBytes);
});

test('if copying an oversized vault fails, nothing is restored', async (t) => {
  const { vault, vaultPath, directory, id } = await fixture(t, { unlocked: false });
  await fs.writeFile(vaultPath, Buffer.alloc(MAX_VAULT_BYTES + 1024, 0x61));
  const h = harness(t, vault);
  const token = await h.preview(id);
  const before = await capture(vault, directory);
  const realCopy = fs.copyFile;
  // A copy that comes out different (as if vault.json changed during it) must be caught too.
  t.mock.method(fs, 'copyFile', async (from, to, mode) => {
    await realCopy(from, to, mode);
    await fs.appendFile(to, 'x');
  });

  assert.deepEqual(await h.restore(id, token), { success: false, error: PRE_RESTORE_ERROR });
  t.mock.restoreAll();
  await assertUnchanged(vault, directory, before, 'oversized copy mismatch');
});

test('vault.restoreBackup checks its id and expected state before any file is read', async (t) => {
  const { vault, directory, id } = await fixture(t);
  const before = await capture(vault, directory);
  const opens = t.mock.method(fs, 'open');
  await assert.rejects(vault.restoreBackup('../vault.json', { backupDigest: 'x', vaultState: 'absent' }), { message: 'Invalid backup id.' });
  for (const expected of [undefined, null, {}, { backupDigest: 'x' }, { backupDigest: 1, vaultState: 'absent' }]) {
    await assert.rejects(vault.restoreBackup(id, expected), { message: TOKEN_ERROR });
  }
  assert.equal(opens.mock.callCount(), 0);
  t.mock.restoreAll();
  await assertUnchanged(vault, directory, before, 'bad arguments');
});

test('writeVaultFile still writes the same pretty-printed envelope', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  await vault.saveEntry(makeEntry());
  const text = await fs.readFile(vaultPath, 'utf8');
  assert.equal(text, JSON.stringify(JSON.parse(text), null, 2));
  vault.lock();
  const reopened = new PasswordVault(vaultPath);
  t.after(() => reopened.lock());
  await reopened.unlock(MASTER_PASSWORD);
  assert.equal((await reopened.loadEntries()).length, 1);
});
