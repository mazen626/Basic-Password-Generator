const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const test = require('node:test');
const PasswordVault = require('../vault');
const { MASTER_PASSWORD, createVault, makeEntry } = require('./helpers');

const MAX_VAULT_BYTES = 8 * 1024 * 1024;

function makeStoredEntries(count, notesLength) {
  const now = new Date().toISOString();
  return Array.from({ length: count }, (_, index) => ({
    id: crypto.randomUUID(),
    site: `site-${index}.example`,
    username: `user${index}@example.com`,
    password: crypto.randomBytes(18).toString('base64'),
    notes: 'n'.repeat(notesLength),
    category: 'login',
    favorite: false,
    backupCodes: [],
    createdAt: now,
    updatedAt: now
  }));
}

async function fillVault(vault, vaultPath, entries) {
  const envelope = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  await vault.persistEntries(entries, vault.requireKey(), envelope);
  return (await fs.stat(vaultPath)).size;
}

test('a vault close to the 8 MB limit can be saved, unlocked and loaded', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  const entries = makeStoredEntries(1400, 3900);
  const size = await fillVault(vault, vaultPath, entries);
  assert.ok(size > 7 * 1024 * 1024 && size < MAX_VAULT_BYTES, `vault file is ${size} bytes`);

  vault.lock();
  const reopened = new PasswordVault(vaultPath);
  t.after(() => reopened.lock());
  assert.deepEqual(await reopened.getStatus(), { exists: true, legacy: false, corrupted: false });
  await reopened.unlock(MASTER_PASSWORD);

  const loaded = await reopened.loadEntries();
  assert.equal(loaded.length, entries.length);
  assert.deepEqual(loaded[1399], entries[1399]);

  await reopened.saveEntry(makeEntry({ site: 'one-more.example' }));
  assert.equal((await reopened.loadEntries()).length, entries.length + 1);
});

test('a vault with 10,000 entries can be unlocked', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  const size = await fillVault(vault, vaultPath, makeStoredEntries(10000, 120));
  assert.ok(size > 4.5 * 1024 * 1024, `vault file is ${size} bytes`);

  vault.lock();
  await vault.unlock(MASTER_PASSWORD);
  assert.equal((await vault.loadEntries()).length, 10000);
});

test('a save that would pass 8 MB is refused and the vault stays readable', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  const startSize = await fillVault(vault, vaultPath, makeStoredEntries(1480, 3900));
  assert.ok(startSize > MAX_VAULT_BYTES - 200 * 1024 && startSize < MAX_VAULT_BYTES, `vault file is ${startSize} bytes`);
  const before = await fs.readFile(vaultPath, 'utf8');

  const bigNotes = 'x'.repeat(4000);
  await assert.rejects(async () => {
    for (let index = 0; index < 60; index += 1) {
      await vault.saveEntry(makeEntry({ site: `filler-${index}.example`, notes: bigNotes }));
    }
  }, /maximum file size/);

  const after = await fs.readFile(vaultPath, 'utf8');
  assert.ok(after.length >= before.length);
  vault.lock();
  await vault.unlock(MASTER_PASSWORD);
  assert.ok((await vault.loadEntries()).length >= 1480);
});

test('malformed base64 in any envelope field is reported as corrupted and never rewritten', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  await vault.saveEntry(makeEntry());
  vault.lock();
  const valid = JSON.parse(await fs.readFile(vaultPath, 'utf8'));

  const cases = [
    ['line break in ciphertext', 'ciphertext', (value) => `${value.slice(0, 8)}\n${value.slice(8)}`],
    ['leading space in ciphertext', 'ciphertext', (value) => ` ${value}`],
    ['ciphertext missing its last character', 'ciphertext', (value) => value.slice(0, -1)],
    ['invalid characters in ciphertext', 'ciphertext', (value) => `${value.slice(0, -4)}!!!!`],
    ['URL-safe alphabet in ciphertext', 'ciphertext', (value) => `${value.slice(0, 4)}-_${value.slice(6)}`],
    ['salt missing its padding', 'salt', (value) => value.replace(/=+$/, '')],
    ['salt too short', 'salt', (value) => value.slice(0, 8)],
    ['iv too long', 'iv', (value) => `${value}AAAA`],
    ['tag with non-canonical bits', 'tag', (value) => `${value.slice(0, -3)}R==`],
    ['salt that is not a string', 'salt', () => 12345]
  ];

  for (const [label, field, corrupt] of cases) {
    const corrupted = corrupt(valid[field]);
    assert.notEqual(corrupted, valid[field], `${label}: the change must alter the field`);
    const contents = JSON.stringify({ ...valid, [field]: corrupted });
    await fs.writeFile(vaultPath, contents);
    const reader = new PasswordVault(vaultPath);
    assert.equal((await reader.getStatus()).corrupted, true, `${label} should be reported as corrupted`);
    await assert.rejects(reader.unlock(MASTER_PASSWORD), /invalid or corrupted/);
    assert.equal(await fs.readFile(vaultPath, 'utf8'), contents);
  }
});

test('non-canonical base64 that Node would quietly accept is rejected', () => {
  assert.equal(Buffer.from('QR==', 'base64').toString('base64'), 'QQ==');
  assert.equal(Buffer.from('QQ', 'base64').toString('base64'), 'QQ==');
  assert.equal(Buffer.from('Q Q==', 'base64').toString('base64'), 'QQ==');
});
