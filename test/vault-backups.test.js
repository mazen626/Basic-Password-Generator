// Phase 2A milestone 2A.1: the read-only backup inventory (docs/PHASE-2A-DESIGN.md, parts A and B)
// and the kind-tagged names of new backups (owner decision 5).
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const PasswordVault = require('../vault');
const { registerCsvHandlers } = require('../csv-transfer');
const { MASTER_PASSWORD, createTempDirectory, createVault } = require('./helpers');

const NEW_PASSWORD = 'a brand new master password';
const UUID = '0f8e2b7c-1a2b-4c3d-8e9f-a0b1c2d3e4f5';
const MS = 1762900000000;
const ITEM_KEYS = ['createdAt', 'id', 'kind', 'passwordHint', 'size', 'status', 'version'];

const names = {
  backup: (ms = MS, uuid = UUID) => `vault-backup-${ms}-${uuid}.bak`,
  'pre-upgrade': (ms = MS, uuid = UUID, version = 2) => `vault.json.v${version}-${ms}-${uuid}.bak`,
  'pre-restore': (ms = MS, uuid = UUID) => `vault-before-restore-${ms}-${uuid}.bak`,
  'pre-password-change': (ms = MS, uuid = UUID) => `vault-before-password-change-${ms}-${uuid}.bak`,
  'pre-import': (ms = MS, uuid = UUID) => `vault-before-import-${ms}-${uuid}.bak`
};

// The current vault file with some envelope fields replaced, as text.
async function envelopeText(vaultPath, overrides = {}) {
  return JSON.stringify({ ...JSON.parse(await fs.readFile(vaultPath, 'utf8')), ...overrides }, null, 2);
}

const byId = (items) => Object.fromEntries(items.map((item) => [item.id, item]));

test('every backup name pattern is recognized and labeled with its kind and date', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const current = await fs.readFile(vaultPath, 'utf8');
  const files = {
    [names.backup(MS + 1)]: current,
    [names['pre-upgrade'](MS + 2, UUID, 2)]: await envelopeText(vaultPath, { version: 2 }),
    [names['pre-upgrade'](MS + 3, UUID, 1)]: await envelopeText(vaultPath, { version: 1 }),
    [names['pre-restore'](MS + 4)]: current,
    [names['pre-password-change'](MS + 5)]: current,
    [names['pre-import'](MS + 6)]: current
  };
  for (const [name, contents] of Object.entries(files)) await fs.writeFile(path.join(directory, name), contents);

  const items = await vault.listBackups();
  assert.equal(items.length, 6);
  items.forEach((item) => assert.deepEqual(Object.keys(item).sort(), ITEM_KEYS, 'only the documented fields, never the salt'));
  assert.deepEqual(items.map((item) => item.kind),
    ['pre-import', 'pre-password-change', 'pre-restore', 'pre-upgrade', 'pre-upgrade', 'backup'], 'newest first');
  assert.deepEqual(byId(items)[names.backup(MS + 1)], {
    id: names.backup(MS + 1),
    kind: 'backup',
    createdAt: new Date(MS + 1).toISOString(),
    size: Buffer.byteLength(current),
    version: 3,
    status: 'valid',
    passwordHint: 'current'
  });
  assert.equal(byId(items)[names['pre-upgrade'](MS + 2, UUID, 2)].version, 2);
  assert.equal(byId(items)[names['pre-upgrade'](MS + 3, UUID, 1)].version, 1);
  assert.equal(items.every((item) => item.status === 'valid'), true);
});

test('the pre-upgrade pattern follows the vault file name, with its regex characters escaped', async (t) => {
  const directory = await createTempDirectory(t);
  const vault = new PasswordVault(path.join(directory, 'my.vault+1.json'));
  t.after(() => vault.lock());
  await vault.unlock(MASTER_PASSWORD, MASTER_PASSWORD);
  const contents = await envelopeText(vault.filePath, { version: 2 });
  await fs.writeFile(path.join(directory, `my.vault+1.json.v2-${MS}-${UUID}.bak`), contents);
  await fs.writeFile(path.join(directory, `myXvault+1.json.v2-${MS}-${UUID}.bak`), contents);
  await fs.writeFile(path.join(directory, `my.vaultt1.json.v2-${MS}-${UUID}.bak`), contents);
  await fs.writeFile(path.join(directory, names['pre-upgrade']()), contents);

  assert.deepEqual((await vault.listBackups()).map((item) => item.id), [`my.vault+1.json.v2-${MS}-${UUID}.bak`]);
});

test('the vault file, its temp file and unrelated files are ignored', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const current = await fs.readFile(vaultPath, 'utf8');
  const ignored = [
    'vault.json.tmp',
    'other.bak',
    'settings.json',
    'Preferences',
    `other.json.v2-${MS}-${UUID}.bak`,
    `vault.json.v3-${MS}-${UUID}.bak`,
    `vault-backup-${String(MS).slice(1)}-${UUID}.bak`,
    `vault-backup-${MS}0-${UUID}.bak`,
    `vault-backup-${MS}-${UUID.toUpperCase()}.bak`,
    `VAULT-BACKUP-${MS}-${UUID}.bak`,
    `vault-backup-${MS}-${UUID}.BAK`,
    `vault-backup-${MS}-${UUID}.bak.tmp`,
    `x-vault-backup-${MS}-${UUID}.bak`,
    `vault-backup-${MS}-${UUID.replace(/-/g, '')}.bak`
  ];
  for (const name of ignored) await fs.writeFile(path.join(directory, name), current);

  assert.deepEqual(await vault.listBackups(), []);
});

test('a folder with a backup name is not listed', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  await fs.mkdir(path.join(directory, names.backup(MS + 1)));
  await fs.copyFile(vaultPath, path.join(directory, names.backup(MS)));

  assert.deepEqual((await vault.listBackups()).map((item) => item.id), [names.backup(MS)]);
});

test('a symlink with a backup name is not listed', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  try {
    await fs.symlink(vaultPath, path.join(directory, names.backup(MS + 1)), 'file');
  } catch (error) {
    // Windows refuses file symlinks without Developer Mode or admin rights.
    t.skip(`symlinks are not available here (${error.code})`);
    return;
  }
  await fs.copyFile(vaultPath, path.join(directory, names.backup(MS)));

  assert.deepEqual((await vault.listBackups()).map((item) => item.id), [names.backup(MS)]);
});

test('a junction or folder link with a backup name is not listed', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const target = path.join(directory, 'elsewhere');
  await fs.mkdir(target);
  // A junction on Windows (allowed without admin rights), a folder symlink elsewhere.
  await fs.symlink(target, path.join(directory, names.backup(MS + 1)), 'junction');
  await fs.copyFile(vaultPath, path.join(directory, names.backup(MS)));

  assert.deepEqual((await vault.listBackups()).map((item) => item.id), [names.backup(MS)]);
});

test('a backup over 8 MB is listed as too large without being opened', async (t) => {
  const { vault, directory } = await createVault(t);
  const large = path.join(directory, names.backup());
  await fs.writeFile(large, '');
  await fs.truncate(large, 8 * 1024 * 1024 + 1);
  const opened = [];
  const realOpen = fs.open;
  t.mock.method(fs, 'open', async (filePath, ...rest) => {
    opened.push(path.basename(String(filePath)));
    return realOpen(filePath, ...rest);
  });

  assert.deepEqual(await vault.listBackups(), [{
    id: names.backup(),
    kind: 'backup',
    createdAt: new Date(MS).toISOString(),
    size: 8 * 1024 * 1024 + 1,
    version: null,
    status: 'too-large',
    passwordHint: 'unknown'
  }]);
  assert.deepEqual(opened, ['vault.json'], 'only the vault file is read, for the password hint');
});

test('damaged backups and a version that does not match the name are listed as invalid', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const current = await fs.readFile(vaultPath, 'utf8');
  const cases = {
    truncated: [names.backup(MS + 1), current.slice(0, Math.floor(current.length / 2))],
    'not JSON': [names.backup(MS + 2), 'this is not json'],
    'empty file': [names.backup(MS + 3), ''],
    'unsupported version': [names.backup(MS + 4), await envelopeText(vaultPath, { version: 4 })],
    'bad base64': [names.backup(MS + 5), await envelopeText(vaultPath, { iv: 'not base64!' })],
    'wrong length': [names.backup(MS + 6), await envelopeText(vaultPath, { salt: crypto.randomBytes(8).toString('base64') })],
    'v1 name, v3 file': [names['pre-upgrade'](MS + 7, UUID, 1), current],
    'v2 name, v1 file': [names['pre-upgrade'](MS + 8, UUID, 2), await envelopeText(vaultPath, { version: 1 })]
  };
  for (const [name, contents] of Object.values(cases)) await fs.writeFile(path.join(directory, name), contents);

  const items = byId(await vault.listBackups());
  for (const [label, [name, contents]] of Object.entries(cases)) {
    assert.deepEqual(items[name], {
      id: name,
      kind: name.startsWith('vault.json') ? 'pre-upgrade' : 'backup',
      createdAt: items[name].createdAt,
      size: Buffer.byteLength(contents),
      version: null,
      status: 'invalid',
      passwordHint: 'unknown'
    }, label);
  }
});

test('valid backups come before invalid ones, each newest first', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  await fs.copyFile(vaultPath, path.join(directory, names.backup(MS + 1)));
  await fs.writeFile(path.join(directory, names.backup(MS + 9)), 'junk');
  await fs.copyFile(vaultPath, path.join(directory, names['pre-import'](MS + 5)));
  await fs.writeFile(path.join(directory, names.backup(MS + 2)), 'junk');

  assert.deepEqual((await vault.listBackups()).map((item) => item.id),
    [names['pre-import'](MS + 5), names.backup(MS + 1), names.backup(MS + 9), names.backup(MS + 2)]);
});

test('the password hint compares salt and iterations with the current vault', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const { backupName: before } = await vault.changeMasterPassword(MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD);
  const after = await vault.createBackup();
  const iterations = await envelopeText(vaultPath, { iterations: 700000 });
  await fs.writeFile(path.join(directory, names.backup(MS)), iterations);

  let items = byId(await vault.listBackups());
  assert.equal(items[before].passwordHint, 'other', 'made before the password change');
  assert.equal(items[after].passwordHint, 'current');
  assert.equal(items[names.backup(MS)].passwordHint, 'other', 'same salt, different iterations');

  await fs.writeFile(vaultPath, 'damaged');
  items = await vault.listBackups();
  assert.deepEqual(items.map((item) => item.passwordHint), ['unknown', 'unknown', 'unknown'], 'vault.json invalid');
  assert.equal(items.every((item) => item.status === 'valid'), true);

  await fs.rm(vaultPath);
  items = await vault.listBackups();
  assert.deepEqual(items.map((item) => item.passwordHint), ['unknown', 'unknown', 'unknown'], 'vault.json missing');
});

test('the list works while the vault is locked and never changes a file', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const backupName = await vault.createBackup();
  vault.lock();
  const before = await fs.readFile(vaultPath);

  const items = await vault.listBackups();
  assert.deepEqual(items.map((item) => [item.id, item.status, item.passwordHint]), [[backupName, 'valid', 'current']]);
  assert.equal(vault.isUnlocked(), false);
  assert.deepEqual(await fs.readFile(vaultPath), before);
  assert.deepEqual((await fs.readdir(directory)).sort(), [backupName, 'vault.json'].sort());
});

test('a backup removed during the scan is left out, and one that cannot be read is unreadable', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const gone = names.backup(MS + 1);
  const locked = names.backup(MS + 2);
  const kept = names.backup(MS + 3);
  for (const name of [gone, locked, kept]) await fs.copyFile(vaultPath, path.join(directory, name));
  const size = (await fs.stat(vaultPath)).size;

  const realLstat = fs.lstat;
  t.mock.method(fs, 'lstat', async (filePath, ...rest) => {
    if (path.basename(String(filePath)) === gone) await fs.rm(filePath);
    return realLstat(filePath, ...rest);
  });
  const realOpen = fs.open;
  t.mock.method(fs, 'open', async (filePath, ...rest) => {
    if (path.basename(String(filePath)) === locked) {
      throw Object.assign(new Error(`EBUSY: resource busy or locked, open '${filePath}'`), { code: 'EBUSY' });
    }
    return realOpen(filePath, ...rest);
  });

  const items = await vault.listBackups();
  assert.deepEqual(items.map((item) => item.id), [kept, locked]);
  assert.deepEqual(byId(items)[locked], {
    id: locked,
    kind: 'backup',
    createdAt: new Date(MS + 2).toISOString(),
    size,
    version: null,
    status: 'unreadable',
    passwordHint: 'unknown'
  });
});

test('a folder that cannot be read gives an error without its path', async (t) => {
  const { vault, directory } = await createVault(t);
  t.mock.method(fs, 'readdir', async () => {
    throw Object.assign(new Error(`EACCES: permission denied, scandir '${directory}'`), { code: 'EACCES' });
  });
  await assert.rejects(vault.listBackups(), { message: 'Could not read the backup folder.' });
});

test('a missing vault folder lists no backups', async (t) => {
  const directory = await createTempDirectory(t);
  const vault = new PasswordVault(path.join(directory, 'missing', 'vault.json'));
  assert.deepEqual(await vault.listBackups(), []);
});

test('backup ids are accepted only in their exact form', async (t) => {
  const { vault } = await createVault(t, { unlocked: false });
  for (const [kind, make] of Object.entries(names)) {
    assert.deepEqual(vault.validateBackupId(make()), {
      kind,
      createdAt: MS,
      legacyVersion: kind === 'pre-upgrade' ? 2 : null
    });
  }

  const rejected = [
    undefined, null, 42, {}, [names.backup()], '',
    '..', '.', 'vault.json', 'vault.json.tmp',
    `../${names.backup()}`,
    `..\\${names.backup()}`,
    `sub/${names.backup()}`,
    `C:\\Users\\${names.backup()}`,
    `C:${names.backup()}`,
    `\\\\server\\share\\${names.backup()}`,
    `${names.backup()}/..`,
    `${names.backup()}\0`,
    ` ${names.backup()}`,
    `${names.backup()}\n`,
    names.backup(MS, UUID.toUpperCase()),
    names.backup(MS, UUID.replace('a', 'A')),
    names.backup(MS, UUID.replace('f', 'g')),
    names.backup(123),
    names.backup(`${MS}1`),
    names['pre-upgrade'](MS, UUID, 3),
    `x${names.backup()}`,
    'a'.repeat(129),
    `${names.backup()}${'a'.repeat(128)}`
  ];
  for (const id of rejected) {
    assert.throws(() => vault.validateBackupId(id), { message: 'Invalid backup id.' }, JSON.stringify(id));
    assert.equal(PasswordVault.parseBackupId(id), null, JSON.stringify(id));
  }
});

// --- Decision 5: new backups say why they were made ---

test('manual, password-change and CSV-import backups get their own names and kinds', async (t) => {
  const { vault, directory } = await createVault(t);
  const manual = await vault.createBackup();
  const { backupName: passwordChange } = await vault.changeMasterPassword(MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD);

  const csvPath = path.join(directory, 'passwords.csv');
  await fs.writeFile(csvPath, 'name,url,username,password\nGitHub,https://github.com,alice,Sup3r-Secret!\n');
  const handlers = {};
  registerCsvHandlers({
    registerVaultHandler: (channel, operation) => { handlers[channel] = operation; },
    getVault: () => vault,
    getParentWindow: () => null,
    dialog: {
      showOpenDialog: async () => ({ canceled: false, filePaths: [csvPath] }),
      showMessageBox: async () => ({ response: 1 }) // import and keep the CSV file
    },
    onActivity: () => {}
  });
  const imported = await handlers['vault:import-csv']();
  assert.equal(imported.success, true);

  assert.match(manual, /^vault-backup-\d{13}-[0-9a-f-]{36}\.bak$/);
  assert.match(passwordChange, /^vault-before-password-change-\d{13}-[0-9a-f-]{36}\.bak$/);
  assert.match(imported.backupName, /^vault-before-import-\d{13}-[0-9a-f-]{36}\.bak$/);

  const items = byId(await vault.listBackups());
  assert.equal(items[manual].kind, 'backup');
  assert.equal(items[passwordChange].kind, 'pre-password-change');
  assert.equal(items[imported.backupName].kind, 'pre-import');
  assert.equal(items[imported.backupName].passwordHint, 'current');
  assert.equal(Object.keys(items).length, 3);
});

test('createBackup refuses an unknown kind', async (t) => {
  const { vault, directory } = await createVault(t);
  await assert.rejects(vault.createBackup('../evil'), { message: 'Unknown backup kind.' });
  await assert.rejects(vault.createBackup('pre-upgrade'), { message: 'Unknown backup kind.' });
  assert.deepEqual(await fs.readdir(directory), ['vault.json']);
});
