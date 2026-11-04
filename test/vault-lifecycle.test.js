const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const PasswordVault = require('../vault');
const { MASTER_PASSWORD, createTempDirectory, createVault, makeEntry } = require('./helpers');

test('creating a vault writes an encrypted v2 envelope and unlocks it', async (t) => {
  const { vaultPath, vault } = await createVault(t, { unlocked: false });

  assert.deepEqual(await vault.getStatus(), { exists: false, legacy: false, corrupted: false });
  assert.deepEqual(await vault.unlock(MASTER_PASSWORD, MASTER_PASSWORD), { created: true, migrated: false });
  assert.equal(vault.isUnlocked(), true);

  const envelope = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  assert.deepEqual(Object.keys(envelope).sort(), ['cipher', 'ciphertext', 'iterations', 'iv', 'kdf', 'salt', 'tag', 'version']);
  assert.equal(envelope.version, 3);
  assert.equal(envelope.kdf, 'pbkdf2-sha256');
  assert.equal(envelope.iterations, 600000);
  assert.equal(envelope.cipher, 'aes-256-gcm');
  assert.deepEqual(await vault.loadEntries(), []);
  assert.deepEqual(await vault.getStatus(), { exists: true, legacy: false, corrupted: false });
});

test('creating a vault requires a matching confirmation and a valid master password', async (t) => {
  const { vaultPath, vault } = await createVault(t, { unlocked: false });

  await assert.rejects(vault.unlock(MASTER_PASSWORD, 'something else'), /confirmation does not match/);
  await assert.rejects(vault.unlock(MASTER_PASSWORD), /confirmation does not match/);
  await assert.rejects(vault.unlock('short', 'short'), /between 8 and 1024/);
  await assert.rejects(vault.unlock('x'.repeat(1025), 'x'.repeat(1025)), /between 8 and 1024/);
  await assert.rejects(fs.access(vaultPath), { code: 'ENOENT' });
  assert.equal(vault.isUnlocked(), false);
});

test('a wrong master password is rejected and leaves the vault file unchanged', async (t) => {
  const { vaultPath, vault } = await createVault(t);
  await vault.saveEntry(makeEntry());
  vault.lock();
  const before = await fs.readFile(vaultPath, 'utf8');

  await assert.rejects(vault.unlock('wrong master password'), /Incorrect master password or vault data is corrupted\./);
  assert.equal(vault.isUnlocked(), false);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), before);
});

test('entries survive lock and unlock with a new vault instance', async (t) => {
  const { vaultPath, vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: '  github.com  ', notes: 'work account', category: 'work', favorite: true }));
  vault.lock();

  const reopened = new PasswordVault(vaultPath);
  t.after(() => reopened.lock());
  assert.deepEqual(await reopened.unlock(MASTER_PASSWORD), { created: false, migrated: false });
  const [entry] = await reopened.loadEntries();

  assert.equal(entry.site, 'github.com');
  assert.equal(entry.username, 'alice');
  assert.equal(entry.password, 'secret-password');
  assert.equal(entry.notes, 'work account');
  assert.equal(entry.category, 'work');
  assert.equal(entry.favorite, true);
  assert.match(entry.id, /^[0-9a-f-]{36}$/);
  assert.equal(entry.createdAt, entry.updatedAt);
});

test('plaintext entry data never appears in the vault file', async (t) => {
  const { vaultPath, vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'plaintext-site.example', username: 'plaintext-user', password: 'plaintext-password', notes: 'plaintext-note' }));

  const contents = await fs.readFile(vaultPath, 'utf8');
  for (const value of ['plaintext-site', 'plaintext-user', 'plaintext-password', 'plaintext-note', MASTER_PASSWORD]) {
    assert.equal(contents.includes(value), false, `${value} should not be stored in plaintext`);
  }
});

test('every write uses a new IV but keeps the salt', async (t) => {
  const { vaultPath, vault } = await createVault(t);
  const first = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  await vault.saveEntry(makeEntry());
  const second = JSON.parse(await fs.readFile(vaultPath, 'utf8'));

  assert.equal(second.salt, first.salt);
  assert.notEqual(second.iv, first.iv);
});

test('updating an entry changes its fields and only bumps updatedAt when the password changes', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry());
  const [original] = await vault.loadEntries();

  await vault.updateEntry(original.id, makeEntry({ username: 'bob', notes: 'new note', category: 'email', favorite: true }));
  const [metadataOnly] = await vault.loadEntries();
  assert.equal(metadataOnly.username, 'bob');
  assert.equal(metadataOnly.notes, 'new note');
  assert.equal(metadataOnly.category, 'email');
  assert.equal(metadataOnly.favorite, true);
  assert.equal(metadataOnly.createdAt, original.createdAt);
  assert.equal(metadataOnly.updatedAt, original.updatedAt);

  await new Promise((resolve) => setTimeout(resolve, 5));
  await vault.updateEntry(original.id, makeEntry({ password: 'a-new-password' }));
  const [passwordChanged] = await vault.loadEntries();
  assert.equal(passwordChanged.password, 'a-new-password');
  assert.equal(passwordChanged.createdAt, original.createdAt);
  assert.notEqual(passwordChanged.updatedAt, original.updatedAt);
});

test('deleting an entry removes only that entry', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'one.example' }));
  await vault.saveEntry(makeEntry({ site: 'two.example' }));
  const entries = await vault.loadEntries();

  await vault.deleteEntry(entries[0].id);
  assert.deepEqual((await vault.loadEntries()).map((entry) => entry.site), ['two.example']);
  await assert.rejects(vault.deleteEntry(entries[0].id), /Entry not found/);
  await assert.rejects(vault.updateEntry(entries[0].id, makeEntry()), /Entry not found/);
});

test('duplicate sites are rejected case-insensitively, ignoring surrounding spaces', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'Example.com' }));
  await vault.saveEntry(makeEntry({ site: 'other.example' }));

  await assert.rejects(vault.saveEntry(makeEntry({ site: '  example.COM ' })), /already exists/);
  const [, other] = await vault.loadEntries();
  await assert.rejects(vault.updateEntry(other.id, makeEntry({ site: 'EXAMPLE.com' })), /already exists/);
  await vault.updateEntry(other.id, makeEntry({ site: 'Other.Example' }));
  assert.equal((await vault.loadEntries()).length, 2);
});

test('invalid entries are rejected before anything is written', async (t) => {
  const { vaultPath, vault } = await createVault(t);
  const before = await fs.readFile(vaultPath, 'utf8');
  const invalidEntries = [
    [{ ...makeEntry(), site: '   ' }, /Site must contain/],
    [{ ...makeEntry(), site: 'x'.repeat(201) }, /Site must contain/],
    [{ ...makeEntry(), username: 'x'.repeat(256) }, /Username must be/],
    [{ ...makeEntry(), password: '' }, /Password must contain/],
    [{ ...makeEntry(), password: 'x'.repeat(4097) }, /Password must contain/],
    [{ ...makeEntry(), notes: 'x'.repeat(4001) }, /Notes must be/],
    [{ ...makeEntry(), category: 'banking' }, /valid category/],
    [{ ...makeEntry(), favorite: 'yes' }, /Favorite must be/],
    [{ site: 'missing.example', password: 'secret' }, /Entry must include/],
    [null, /Entry must include/]
  ];

  for (const [entry, message] of invalidEntries) {
    await assert.rejects(vault.saveEntry(entry), message);
  }
  await assert.rejects(vault.updateEntry('not-a-uuid', makeEntry()), /Invalid entry id/);
  await assert.rejects(vault.deleteEntry('not-a-uuid'), /Invalid entry id/);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), before);
});

test('vault operations require an unlocked vault', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry());
  const [entry] = await vault.loadEntries();
  vault.lock();

  assert.equal(vault.isUnlocked(), false);
  await assert.rejects(vault.loadEntries(), /Unlock the vault first/);
  await assert.rejects(vault.saveEntry(makeEntry({ site: 'new.example' })), /Unlock the vault first/);
  await assert.rejects(vault.updateEntry(entry.id, makeEntry()), /Unlock the vault first/);
  await assert.rejects(vault.deleteEntry(entry.id), /Unlock the vault first/);
});

test('concurrent saves are serialized and none are lost', async (t) => {
  const { vault } = await createVault(t);
  const sites = Array.from({ length: 15 }, (_, index) => `site-${index}.example`);

  await Promise.all(sites.map((site) => vault.saveEntry(makeEntry({ site }))));
  assert.deepEqual((await vault.loadEntries()).map((entry) => entry.site).sort(), [...sites].sort());
});

test('a failed write does not block later writes', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'taken.example' }));

  const results = await Promise.allSettled([
    vault.saveEntry(makeEntry({ site: 'taken.example' })),
    vault.saveEntry(makeEntry({ site: 'free.example' }))
  ]);
  assert.equal(results[0].status, 'rejected');
  assert.equal(results[1].status, 'fulfilled');
  assert.deepEqual((await vault.loadEntries()).map((entry) => entry.site), ['taken.example', 'free.example']);
});

test('createBackup copies the encrypted vault byte for byte', async (t) => {
  const { directory, vaultPath, vault } = await createVault(t);
  await vault.saveEntry(makeEntry());

  const backupName = await vault.createBackup();
  assert.match(backupName, /^vault-backup-\d+-[0-9a-f-]{36}\.bak$/);
  assert.deepEqual(await fs.readFile(path.join(directory, backupName)), await fs.readFile(vaultPath));
});

test('createBackup fails clearly when there is no vault', async (t) => {
  const directory = await createTempDirectory(t);
  const vault = new PasswordVault(path.join(directory, 'vault.json'));

  await assert.rejects(vault.createBackup(), /no vault file to back up/);
});
