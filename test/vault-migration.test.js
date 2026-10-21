const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const PasswordVault = require('../vault');

function createLegacyEnvelope(entries, masterPassword) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(masterPassword, salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(entries), 'utf8'), cipher.final()]);
  key.fill(0);
  return {
    version: 1,
    kdf: 'pbkdf2-sha256',
    iterations: 100000,
    cipher: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

test('v1 unlock preserves metadata and backs up the original vault before v2 rewrite', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'password-vault-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));

  const vaultPath = path.join(directory, 'vault.json');
  const originalEntry = {
    id: crypto.randomUUID(),
    site: 'Example',
    username: 'alice',
    password: 'secret-one',
    notes: 'recovery details',
    category: 'email',
    favorite: true,
    createdAt: '2024-01-02T03:04:05.000Z',
    updatedAt: '2025-06-07T08:09:10.000Z'
  };
  const oldEntry = { site: 'Legacy', password: 'secret-two' };
  const originalContents = JSON.stringify(createLegacyEnvelope([originalEntry, oldEntry], 'correct horse battery'));
  await fs.writeFile(vaultPath, originalContents);

  const vault = new PasswordVault(vaultPath);
  t.after(() => vault.lock());
  const result = await vault.unlock('correct horse battery');
  const entries = await vault.loadEntries();
  const rewritten = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  const backupName = (await fs.readdir(directory)).find((name) => name.endsWith('.bak'));

  assert.deepEqual(result, { created: false, migrated: true });
  assert.equal(rewritten.version, 2);
  assert.deepEqual(entries[0], originalEntry);
  assert.equal(entries[1].site, oldEntry.site);
  assert.equal(entries[1].password, oldEntry.password);
  assert.equal(entries[1].username, '');
  assert.equal(entries[1].notes, '');
  assert.equal(entries[1].category, 'login');
  assert.equal(entries[1].favorite, false);
  assert.match(entries[1].createdAt, /^\d{4}-\d\d-\d\dT/);
  assert.equal(entries[1].updatedAt, entries[1].createdAt);
  assert.ok(backupName);
  assert.equal(await fs.readFile(path.join(directory, backupName), 'utf8'), originalContents);
});

test('invalid legacy metadata leaves the original vault untouched', async (t) => {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'password-vault-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));

  const vaultPath = path.join(directory, 'vault.json');
  const originalContents = JSON.stringify(createLegacyEnvelope([
    { site: 'Example', password: 'secret', notes: 42 }
  ], 'correct horse battery'));
  await fs.writeFile(vaultPath, originalContents);

  const vault = new PasswordVault(vaultPath);
  t.after(() => vault.lock());

  await assert.rejects(vault.unlock('correct horse battery'));
  assert.equal(await fs.readFile(vaultPath, 'utf8'), originalContents);
  assert.deepEqual(await fs.readdir(directory), ['vault.json']);
});
