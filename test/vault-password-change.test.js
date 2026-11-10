const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const PasswordVault = require('../vault');
const { MASTER_PASSWORD, createTempDirectory, createVault, makeEntry } = require('./helpers');

const NEW_PASSWORD = 'a brand new master password';

async function backupsIn(directory) {
  return (await fs.readdir(directory)).filter((name) => name.endsWith('.bak'));
}

async function opensWith(vaultPath, password) {
  const reader = new PasswordVault(vaultPath);
  try {
    await reader.unlock(password);
    return await reader.loadEntries();
  } catch {
    return null;
  } finally {
    reader.lock();
  }
}

test('changing the master password re-encrypts the vault and keeps every entry', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example', backupCodes: ['aaa'] }));
  await vault.saveEntry(makeEntry({ site: 'b.example', notes: 'note' }));
  const entriesBefore = await vault.loadEntries();
  const fileBefore = await fs.readFile(vaultPath, 'utf8');
  const envelopeBefore = JSON.parse(fileBefore);

  const { backupName } = await vault.changeMasterPassword(MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD);

  const envelopeAfter = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  assert.notEqual(envelopeAfter.salt, envelopeBefore.salt, 'a fresh salt');
  assert.equal(envelopeAfter.iterations, 600000);
  assert.equal(envelopeAfter.version, 3);
  assert.deepEqual(await opensWith(vaultPath, NEW_PASSWORD), entriesBefore);
  assert.equal(await opensWith(vaultPath, MASTER_PASSWORD), null, 'the old password no longer opens the vault');

  assert.deepEqual(await backupsIn(directory), [backupName]);
  const backupPath = path.join(directory, backupName);
  assert.equal(await fs.readFile(backupPath, 'utf8'), fileBefore, 'the backup is the vault as it was');
  assert.deepEqual(await opensWith(backupPath, MASTER_PASSWORD), entriesBefore, 'the backup opens with the old password');

  await vault.saveEntry(makeEntry({ site: 'c.example' }));
  assert.equal((await opensWith(vaultPath, NEW_PASSWORD)).length, 3, 'later saves use the new key');
});

test('changing the password upgrades an older, lower iteration count', async (t) => {
  const directory = await createTempDirectory(t);
  const vaultPath = path.join(directory, 'vault.json');
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(MASTER_PASSWORD, salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update('[]', 'utf8'), cipher.final()]);
  await fs.writeFile(vaultPath, JSON.stringify({
    version: 3, kdf: 'pbkdf2-sha256', iterations: 100000, cipher: 'aes-256-gcm',
    salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  }));
  const vault = new PasswordVault(vaultPath);
  t.after(() => vault.lock());
  await vault.unlock(MASTER_PASSWORD);

  await vault.changeMasterPassword(MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD);
  assert.equal(JSON.parse(await fs.readFile(vaultPath, 'utf8')).iterations, 600000);
  assert.deepEqual(await opensWith(vaultPath, NEW_PASSWORD), []);
});

test('a wrong current password changes nothing and makes no backup', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  await vault.saveEntry(makeEntry());
  const before = await fs.readFile(vaultPath, 'utf8');

  await assert.rejects(vault.changeMasterPassword('not the right password', NEW_PASSWORD, NEW_PASSWORD), /current master password is incorrect/);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), before);
  assert.deepEqual(await backupsIn(directory), []);
  await vault.saveEntry(makeEntry({ site: 'still-works.example' }));
  assert.equal((await opensWith(vaultPath, MASTER_PASSWORD)).length, 2, 'the old key is still in use');
});

test('invalid new passwords are refused before anything is read or written', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const before = await fs.readFile(vaultPath, 'utf8');
  const cases = [
    ['too short', MASTER_PASSWORD, 'short', 'short', /between 8 and 1024/],
    ['too long', MASTER_PASSWORD, 'x'.repeat(1025), 'x'.repeat(1025), /between 8 and 1024/],
    ['not text', MASTER_PASSWORD, 12345678, 12345678, /between 8 and 1024/],
    ['confirmation differs', MASTER_PASSWORD, NEW_PASSWORD, `${NEW_PASSWORD}!`, /confirmation does not match/],
    ['same as current', MASTER_PASSWORD, MASTER_PASSWORD, MASTER_PASSWORD, /must be different/],
    ['no current password', '', NEW_PASSWORD, NEW_PASSWORD, /Enter your current master password/],
    ['current not text', null, NEW_PASSWORD, NEW_PASSWORD, /Enter your current master password/]
  ];
  for (const [label, current, next, confirmation, error] of cases) {
    await assert.rejects(vault.changeMasterPassword(current, next, confirmation), error, label);
  }
  assert.equal(await fs.readFile(vaultPath, 'utf8'), before);
  assert.deepEqual(await backupsIn(directory), []);
});

test('changing the password needs an unlocked vault', async (t) => {
  const { vault } = await createVault(t);
  vault.lock();
  await assert.rejects(vault.changeMasterPassword(MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD), /Unlock the vault first/);
});

test('if writing the new vault fails, the old vault and old key stay in use', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  await vault.saveEntry(makeEntry());
  const before = await fs.readFile(vaultPath, 'utf8');
  await fs.mkdir(`${vaultPath}.tmp`);

  await assert.rejects(vault.changeMasterPassword(MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD));
  assert.equal(await fs.readFile(vaultPath, 'utf8'), before);
  assert.equal((await backupsIn(directory)).length, 1, 'the backup made first is kept');

  await fs.rm(`${vaultPath}.tmp`, { recursive: true });
  await vault.saveEntry(makeEntry({ site: 'after-failure.example' }));
  assert.equal((await opensWith(vaultPath, MASTER_PASSWORD)).length, 2, 'saves still use the old password');
  assert.equal(await opensWith(vaultPath, NEW_PASSWORD), null);
});

test('saves made at the same time as a password change are all kept', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  await Promise.all([
    vault.saveEntry(makeEntry({ site: 'before.example' })),
    vault.changeMasterPassword(MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD),
    vault.saveEntry(makeEntry({ site: 'after.example' }))
  ]);
  const entries = await opensWith(vaultPath, NEW_PASSWORD);
  assert.deepEqual(entries.map((entry) => entry.site).sort(), ['after.example', 'before.example']);
});

test('backups are flushed to disk, including the one before a password change', async (t) => {
  const { vault } = await createVault(t);
  const synced = [];
  const realOpen = fs.open;
  t.mock.method(fs, 'open', async (filePath, ...rest) => {
    const handle = await realOpen(filePath, ...rest);
    if (String(filePath).endsWith('.bak')) {
      const realSync = handle.sync.bind(handle);
      handle.sync = async () => {
        synced.push(path.basename(String(filePath)));
        return realSync();
      };
    }
    return handle;
  });

  const manual = await vault.createBackup();
  const { backupName } = await vault.changeMasterPassword(MASTER_PASSWORD, NEW_PASSWORD, NEW_PASSWORD);
  assert.deepEqual(synced, [manual, backupName]);
});
