const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const PasswordVault = require('../vault');
const { MASTER_PASSWORD, createVault, makeEntry } = require('./helpers');

async function createSavedVault(t) {
  const context = await createVault(t);
  await context.vault.saveEntry(makeEntry());
  context.vault.lock();
  return context;
}

async function expectCorruptedAndUntouched(vaultPath, contents, unlockError) {
  const vault = new PasswordVault(vaultPath);
  assert.deepEqual(await vault.getStatus(), { exists: true, legacy: false, corrupted: true });
  await assert.rejects(vault.unlock(MASTER_PASSWORD), unlockError);
  assert.equal(vault.isUnlocked(), false);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), contents);
}

test('a truncated vault file is reported as corrupted and never rewritten', async (t) => {
  const { vaultPath } = await createSavedVault(t);
  const contents = await fs.readFile(vaultPath, 'utf8');
  const truncated = contents.slice(0, Math.floor(contents.length / 2));
  await fs.writeFile(vaultPath, truncated);

  await expectCorruptedAndUntouched(vaultPath, truncated, /invalid or corrupted/);
});

test('an empty or non-JSON vault file is reported as corrupted', async (t) => {
  const { vaultPath } = await createSavedVault(t);

  for (const contents of ['', 'not json', '[]', 'null']) {
    await fs.writeFile(vaultPath, contents);
    await expectCorruptedAndUntouched(vaultPath, contents, /invalid or corrupted/);
  }
});

test('unsupported formats and invalid envelope fields are reported as corrupted', async (t) => {
  const { vaultPath } = await createSavedVault(t);
  const envelope = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  const variants = [
    { ...envelope, version: 4 },
    { ...envelope, kdf: 'scrypt' },
    { ...envelope, cipher: 'aes-256-cbc' },
    { ...envelope, iterations: 1000 },
    { ...envelope, salt: 'too-short' },
    { ...envelope, iv: Buffer.alloc(16).toString('base64') },
    { ...envelope, tag: undefined }
  ];

  for (const variant of variants) {
    const contents = JSON.stringify(variant);
    await fs.writeFile(vaultPath, contents);
    await expectCorruptedAndUntouched(vaultPath, contents, /invalid or corrupted/);
  }
});

test('tampered ciphertext fails authentication and the file is left alone', async (t) => {
  const { vaultPath } = await createSavedVault(t);
  const envelope = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  const ciphertext = Buffer.from(envelope.ciphertext, 'base64');
  ciphertext[0] ^= 0xff;
  const contents = JSON.stringify({ ...envelope, ciphertext: ciphertext.toString('base64') });
  await fs.writeFile(vaultPath, contents);

  const vault = new PasswordVault(vaultPath);
  assert.deepEqual(await vault.getStatus(), { exists: true, legacy: false, corrupted: false });
  await assert.rejects(vault.unlock(MASTER_PASSWORD), /Incorrect master password or vault data is corrupted\./);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), contents);
});

test('an oversized vault file is rejected without being parsed', async (t) => {
  const { vaultPath } = await createSavedVault(t);
  const contents = ' '.repeat(8 * 1024 * 1024 + 1);
  await fs.writeFile(vaultPath, contents);

  await expectCorruptedAndUntouched(vaultPath, contents, /too large/);
});

test('a leftover temporary file from an interrupted write is ignored and replaced', async (t) => {
  const { vaultPath } = await createSavedVault(t);
  await fs.writeFile(`${vaultPath}.tmp`, '{"partial":');

  const vault = new PasswordVault(vaultPath);
  t.after(() => vault.lock());
  await vault.unlock(MASTER_PASSWORD);
  assert.equal((await vault.loadEntries()).length, 1);

  await vault.saveEntry(makeEntry({ site: 'after-interruption.example' }));
  assert.equal((await vault.loadEntries()).length, 2);
  await assert.rejects(fs.access(`${vaultPath}.tmp`), { code: 'ENOENT' });
});

test('a write that fails before the rename keeps the previous vault intact', async (t) => {
  const { vaultPath } = await createSavedVault(t);
  const vault = new PasswordVault(vaultPath);
  t.after(() => vault.lock());
  await vault.unlock(MASTER_PASSWORD);
  const before = await fs.readFile(vaultPath, 'utf8');

  // A directory at the temporary path makes the write fail the way a full or locked disk would.
  await fs.mkdir(`${vaultPath}.tmp`);
  await assert.rejects(vault.saveEntry(makeEntry({ site: 'never-saved.example' })));
  assert.equal(await fs.readFile(vaultPath, 'utf8'), before);
  assert.equal((await vault.loadEntries()).length, 1);

  await fs.rm(`${vaultPath}.tmp`, { recursive: true });
  await vault.saveEntry(makeEntry({ site: 'saved-later.example' }));
  assert.equal((await vault.loadEntries()).length, 2);
});

test('a backup restores the vault to its earlier state', async (t) => {
  const { directory, vaultPath } = await createSavedVault(t);
  const vault = new PasswordVault(vaultPath);
  t.after(() => vault.lock());
  const backupName = await vault.createBackup();

  await vault.unlock(MASTER_PASSWORD);
  await vault.saveEntry(makeEntry({ site: 'added-after-backup.example' }));
  vault.lock();
  await fs.copyFile(path.join(directory, backupName), vaultPath);

  await vault.unlock(MASTER_PASSWORD);
  assert.deepEqual((await vault.loadEntries()).map((entry) => entry.site), ['example.com']);
});

test('a vault file removed while unlocked fails loudly instead of silently recreating it', async (t) => {
  const { vaultPath } = await createSavedVault(t);
  const vault = new PasswordVault(vaultPath);
  t.after(() => vault.lock());
  await vault.unlock(MASTER_PASSWORD);
  await fs.rm(vaultPath);

  await assert.rejects(vault.loadEntries(), { code: 'ENOENT' });
  await assert.rejects(vault.saveEntry(makeEntry({ site: 'new.example' })), { code: 'ENOENT' });
  await assert.rejects(fs.access(vaultPath), { code: 'ENOENT' });
});
