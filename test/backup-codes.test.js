const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const PasswordVault = require('../vault');
const { MAX_BACKUP_CODES, parseBackupCodes, findBackupCodeProblem } = require('../backup-codes');
const { MASTER_PASSWORD, createTempDirectory, createVault, makeEntry } = require('./helpers');

const ITERATIONS = 100000;

function encryptFixture(entries, version) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(MASTER_PASSWORD, salt, ITERATIONS, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(entries), 'utf8'), cipher.final()]);
  key.fill(0);
  return JSON.stringify({
    version,
    kdf: 'pbkdf2-sha256',
    iterations: ITERATIONS,
    cipher: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  });
}

function storedEntry(overrides = {}) {
  return {
    id: crypto.randomUUID(),
    site: 'example.com',
    username: 'alice',
    password: 'secret-password',
    notes: 'keep me',
    category: 'email',
    favorite: true,
    createdAt: '2024-01-02T03:04:05.000Z',
    updatedAt: '2025-06-07T08:09:10.000Z',
    ...overrides
  };
}

async function writeFixture(t, contents) {
  const directory = await createTempDirectory(t);
  const vaultPath = path.join(directory, 'vault.json');
  await fs.writeFile(vaultPath, contents);
  const vault = new PasswordVault(vaultPath);
  t.after(() => vault.lock());
  return { directory, vaultPath, vault };
}

async function findEntry(vault, site = 'example.com') {
  return (await vault.loadEntries()).find((entry) => entry.site === site);
}

test('the example layout splits into eight separate codes', () => {
  const pasted = 'adh83re  iuhagsf7  dfasd3  aasd83\nkjasdan kv043da asdlkhg8  asdaddwe';
  assert.deepEqual(parseBackupCodes(pasted), [
    'adh83re', 'iuhagsf7', 'dfasd3', 'aasd83', 'kjasdan', 'kv043da', 'asdlkhg8', 'asdaddwe'
  ]);
});

test('commas, semicolons, tabs and Windows line endings all separate codes', () => {
  assert.deepEqual(parseBackupCodes('aaa,bbb;ccc\tddd\r\neee'), ['aaa', 'bbb', 'ccc', 'ddd', 'eee']);
});

test('hyphens stay inside a code', () => {
  assert.deepEqual(parseBackupCodes('abcde-fghij klmno-pqrst'), ['abcde-fghij', 'klmno-pqrst']);
});

test('list numbers and bullets are not treated as codes', () => {
  assert.deepEqual(parseBackupCodes('1. aaa\n2. bbb\n3) ccc\n(4) ddd\n- eee\n• fff'), ['aaa', 'bbb', 'ccc', 'ddd', 'eee', 'fff']);
  assert.deepEqual(parseBackupCodes('1. 1234 5678\n2. 2345 6789', { splitOnSpaces: false }), ['1234 5678', '2345 6789']);
});

test('numeric codes are kept', () => {
  assert.deepEqual(parseBackupCodes('12345678 87654321'), ['12345678', '87654321']);
});

test('turning off space splitting keeps one code per line', () => {
  assert.deepEqual(parseBackupCodes('1234 5678\n2345   6789\n', { splitOnSpaces: false }), ['1234 5678', '2345 6789']);
  assert.deepEqual(parseBackupCodes('1234 5678\n2345 6789'), ['1234', '5678', '2345', '6789']);
});

test('duplicates and blank input are removed', () => {
  assert.deepEqual(parseBackupCodes('aaa bbb aaa\n\n  \naaa'), ['aaa', 'bbb']);
  assert.deepEqual(parseBackupCodes('   \n\n'), []);
});

test('too many or too long codes are reported', () => {
  const allowed = Array.from({ length: MAX_BACKUP_CODES }, (_, index) => `code${index}`);
  assert.equal(findBackupCodeProblem(allowed), '');
  assert.match(findBackupCodeProblem([...allowed, 'extra']), /up to 50/);
  assert.match(findBackupCodeProblem(['x'.repeat(129)]), /128 characters/);
});

test('a v2 vault upgrades to v3 with a byte-identical backup and no data changes', async (t) => {
  const original = storedEntry();
  const contents = encryptFixture([original], 2);
  const { directory, vaultPath, vault } = await writeFixture(t, contents);

  assert.equal((await vault.getStatus()).legacy, true);
  assert.deepEqual(await vault.unlock(MASTER_PASSWORD), { created: false, migrated: true });

  const rewritten = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  const backupName = (await fs.readdir(directory)).find((name) => name.endsWith('.bak'));
  assert.equal(rewritten.version, 3);
  assert.equal(rewritten.iterations, ITERATIONS);
  assert.match(backupName, /^vault\.json\.v2-/);
  assert.equal(await fs.readFile(path.join(directory, backupName), 'utf8'), contents);
  assert.deepEqual(await vault.loadEntries(), [{ ...original, backupCodes: [] }]);
  assert.equal((await vault.getStatus()).legacy, false);
});

test('an upgraded vault migrates only once', async (t) => {
  const { directory, vault } = await writeFixture(t, encryptFixture([storedEntry()], 2));
  await vault.unlock(MASTER_PASSWORD);
  vault.lock();
  assert.deepEqual(await vault.unlock(MASTER_PASSWORD), { created: false, migrated: false });
  assert.equal((await fs.readdir(directory)).filter((name) => name.endsWith('.bak')).length, 1);
});

test('a v1 vault upgrades straight to v3', async (t) => {
  const { vaultPath, vault } = await writeFixture(t, encryptFixture([{ site: 'old.example', password: 'old-secret' }], 1));
  await vault.unlock(MASTER_PASSWORD);
  const [entry] = await vault.loadEntries();
  assert.equal(JSON.parse(await fs.readFile(vaultPath, 'utf8')).version, 3);
  assert.equal(entry.password, 'old-secret');
  assert.deepEqual(entry.backupCodes, []);
});

test('a malformed v2 vault is left untouched and not backed up', async (t) => {
  const contents = encryptFixture([storedEntry({ extra: 'field' })], 2);
  const { directory, vaultPath, vault } = await writeFixture(t, contents);
  await assert.rejects(vault.unlock(MASTER_PASSWORD), /Incorrect master password or vault data is corrupted/);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), contents);
  assert.deepEqual(await fs.readdir(directory), ['vault.json']);
});

test('a failed upgrade write leaves the v2 vault readable and keeps the backup', async (t) => {
  const contents = encryptFixture([storedEntry()], 2);
  const { directory, vaultPath, vault } = await writeFixture(t, contents);
  await fs.mkdir(`${vaultPath}.tmp`);

  await assert.rejects(vault.unlock(MASTER_PASSWORD), /Could not upgrade the vault/);
  assert.equal(vault.isUnlocked(), false);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), contents);
  assert.ok((await fs.readdir(directory)).some((name) => name.endsWith('.bak')));

  await fs.rmdir(`${vaultPath}.tmp`);
  assert.equal((await vault.unlock(MASTER_PASSWORD)).migrated, true);
});

test('backupCodes on a v2 entry is rejected', async (t) => {
  const contents = encryptFixture([storedEntry({ backupCodes: [] })], 2);
  const { vaultPath, vault } = await writeFixture(t, contents);
  await assert.rejects(vault.unlock(MASTER_PASSWORD), /corrupted/);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), contents);
});

test('saved codes start unused and are encrypted on disk', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  await vault.saveEntry(makeEntry({ backupCodes: ['plain-text-code-1', 'plain-text-code-2'] }));

  const { backupCodes } = await findEntry(vault);
  assert.deepEqual(backupCodes.map(({ code, used }) => [code, used]), [['plain-text-code-1', false], ['plain-text-code-2', false]]);
  assert.notEqual(backupCodes[0].id, backupCodes[1].id);
  assert.equal((await fs.readFile(vaultPath, 'utf8')).includes('plain-text-code'), false);
});

test('a used checkbox survives lock and reopen, and leaves updatedAt alone', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  await vault.saveEntry(makeEntry({ backupCodes: ['aaa', 'bbb'] }));
  const before = await findEntry(vault);

  await vault.setBackupCodeUsed(before.id, before.backupCodes[1].id, true);
  vault.lock();

  const reopened = new PasswordVault(vaultPath);
  t.after(() => reopened.lock());
  await reopened.unlock(MASTER_PASSWORD);
  const after = await findEntry(reopened);
  assert.deepEqual(after.backupCodes.map(({ used }) => used), [false, true]);
  assert.equal(after.updatedAt, before.updatedAt);
  assert.equal(after.password, before.password);

  await reopened.setBackupCodeUsed(after.id, after.backupCodes[1].id, false);
  assert.equal((await findEntry(reopened)).backupCodes[1].used, false);
});

test('editing keeps used state, adds new codes unused and drops removed codes', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ backupCodes: ['keep', 'used', 'remove'] }));
  const entry = await findEntry(vault);
  const usedCode = entry.backupCodes[1];
  await vault.setBackupCodeUsed(entry.id, usedCode.id, true);

  await vault.updateEntry(entry.id, makeEntry({ backupCodes: ['used', 'keep', 'new'] }));

  const { backupCodes } = await findEntry(vault);
  assert.deepEqual(backupCodes.map(({ code, used }) => [code, used]), [['used', true], ['keep', false], ['new', false]]);
  assert.equal(backupCodes[0].id, usedCode.id);
});

test('codes are deleted with their entry', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ backupCodes: ['aaa'] }));
  await vault.deleteEntry((await findEntry(vault)).id);
  assert.deepEqual(await vault.loadEntries(), []);
});

test('invalid code lists are rejected without changing the vault', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  const contents = await fs.readFile(vaultPath, 'utf8');
  const invalidLists = [
    'not-a-list',
    undefined,
    [''],
    [' padded '],
    ['line\nbreak'],
    [42],
    [{ code: 'aaa', used: true }],
    ['same', 'same'],
    ['x'.repeat(129)],
    Array.from({ length: 51 }, (_, index) => `code${index}`)
  ];

  for (const backupCodes of invalidLists) {
    await assert.rejects(vault.saveEntry(makeEntry({ backupCodes })));
  }
  const { backupCodes: _omitted, ...withoutCodes } = makeEntry();
  await assert.rejects(vault.saveEntry(withoutCodes), /backup codes/);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), contents);
});

test('the used call rejects bad ids, bad values and locked vaults', async (t) => {
  const { vault } = await createVault(t);
  await vault.saveEntry(makeEntry({ backupCodes: ['aaa'] }));
  const entry = await findEntry(vault);
  const codeId = entry.backupCodes[0].id;

  await assert.rejects(vault.setBackupCodeUsed('bad-id', codeId, true), /Invalid entry id/);
  await assert.rejects(vault.setBackupCodeUsed(entry.id, 'bad-id', true), /Invalid entry id/);
  await assert.rejects(vault.setBackupCodeUsed(entry.id, codeId, 'yes'), /true or false/);
  await assert.rejects(vault.setBackupCodeUsed(entry.id, crypto.randomUUID(), true), /Backup code not found/);
  await assert.rejects(vault.setBackupCodeUsed(crypto.randomUUID(), codeId, true), /Entry not found/);

  vault.lock();
  await assert.rejects(vault.setBackupCodeUsed(entry.id, codeId, true), /Unlock the vault first/);
});

test('malformed stored codes fail to unlock and leave the file alone', async (t) => {
  const badCodes = [
    'not-a-list',
    [{ id: crypto.randomUUID(), code: 'aaa' }],
    [{ id: crypto.randomUUID(), code: 'aaa', used: 'yes' }],
    [{ id: 'bad-id', code: 'aaa', used: false }],
    [{ id: crypto.randomUUID(), code: 'aaa', used: false, extra: true }]
  ];
  for (const backupCodes of badCodes) {
    const contents = encryptFixture([storedEntry({ backupCodes })], 3);
    const { vaultPath, vault } = await writeFixture(t, contents);
    await assert.rejects(vault.unlock(MASTER_PASSWORD), /corrupted/);
    assert.equal(await fs.readFile(vaultPath, 'utf8'), contents);
  }
});
