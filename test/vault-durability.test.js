const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const PasswordVault = require('../vault');
const { MASTER_PASSWORD, createTempDirectory, createVault, makeEntry } = require('./helpers');

// Records the order of file operations on the vault's temp file. `fail` names one step to break.
function watchWrites(t, { fail } = {}) {
  const events = [];
  const realOpen = fs.open;
  const realRename = fs.rename;
  t.mock.method(fs, 'open', async (filePath, ...rest) => {
    const handle = await realOpen(filePath, ...rest);
    if (!String(filePath).endsWith('.tmp')) return handle;
    events.push('open');
    for (const step of ['writeFile', 'sync', 'close']) {
      const real = handle[step].bind(handle);
      handle[step] = async (...args) => {
        events.push(step);
        if (fail === step) throw new Error(`${step} failed`);
        return real(...args);
      };
    }
    return handle;
  });
  t.mock.method(fs, 'rename', async (...args) => {
    events.push('rename');
    return realRename(...args);
  });
  return events;
}

const FLUSHED_SAVE = ['open', 'writeFile', 'sync', 'close', 'rename'];

test('a save flushes the temp file to disk before it replaces the vault', async (t) => {
  const { vault } = await createVault(t);
  const events = watchWrites(t);
  await vault.saveEntry(makeEntry());
  assert.deepEqual(events, FLUSHED_SAVE);
});

test('every kind of vault write is flushed before the rename', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ backupCodes: ['aaa'] }));
  const [entry] = await vault.loadEntries();
  const writes = {
    'update': () => vault.updateEntry(entry.id, makeEntry({ notes: 'changed', backupCodes: ['aaa'] })),
    'backup code tick': () => vault.setBackupCodeUsed(entry.id, entry.backupCodes[0].id, true),
    'delete': () => vault.deleteEntry(entry.id)
  };

  for (const [label, write] of Object.entries(writes)) {
    const events = watchWrites(t);
    await write();
    assert.deepEqual(events, FLUSHED_SAVE, label);
    t.mock.restoreAll();
  }
});

test('creating a vault and upgrading an old one are flushed too', async (t) => {
  const directory = await createTempDirectory(t);
  const created = new PasswordVault(path.join(directory, 'new', 'vault.json'));
  t.after(() => created.lock());
  let events = watchWrites(t);
  await created.unlock(MASTER_PASSWORD, MASTER_PASSWORD);
  assert.deepEqual(events, FLUSHED_SAVE, 'create');
  t.mock.restoreAll();

  const legacyPath = path.join(directory, 'vault.json');
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(MASTER_PASSWORD, salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify([{ site: 'old.example', password: 'old-secret' }]), 'utf8'), cipher.final()]);
  await fs.writeFile(legacyPath, JSON.stringify({
    version: 1, kdf: 'pbkdf2-sha256', iterations: 100000, cipher: 'aes-256-gcm',
    salt: salt.toString('base64'), iv: iv.toString('base64'), tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  }));
  const upgraded = new PasswordVault(legacyPath);
  t.after(() => upgraded.lock());
  events = watchWrites(t);
  assert.equal((await upgraded.unlock(MASTER_PASSWORD)).migrated, true);
  assert.deepEqual(events, FLUSHED_SAVE, 'upgrade');
});

for (const step of ['writeFile', 'sync']) {
  test(`if ${step} fails, the vault is not replaced and later saves still work`, async (t) => {
    const { vault, vaultPath, directory } = await createVault(t);
    await vault.saveEntry(makeEntry({ site: 'kept.example' }));
    const before = await fs.readFile(vaultPath, 'utf8');

    const events = watchWrites(t, { fail: step });
    await assert.rejects(vault.saveEntry(makeEntry({ site: 'lost.example' })), new RegExp(`${step} failed`));
    assert.equal(events.includes('rename'), false, 'the vault must not be replaced');
    assert.equal(events.at(-1), 'close', 'the file handle must be closed');
    assert.equal(await fs.readFile(vaultPath, 'utf8'), before);
    assert.deepEqual(await fs.readdir(directory), ['vault.json'], 'the temp file must be removed');
    t.mock.restoreAll();

    await vault.saveEntry(makeEntry({ site: 'next.example' }));
    assert.deepEqual((await vault.loadEntries()).map((entry) => entry.site).sort(), ['kept.example', 'next.example']);
  });
}

test('the flushed file is complete: it can be read back by a new vault instance', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  await vault.saveEntry(makeEntry({ notes: 'ünïcödé ✓ notes' }));
  vault.lock();

  const reopened = new PasswordVault(vaultPath);
  t.after(() => reopened.lock());
  await reopened.unlock(MASTER_PASSWORD);
  assert.equal((await reopened.loadEntries())[0].notes, 'ünïcödé ✓ notes');
  assert.equal((await fs.readFile(vaultPath, 'utf8')).endsWith('}'), true);
});
