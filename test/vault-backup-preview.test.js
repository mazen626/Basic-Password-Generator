// Phase 2A milestone 2A.2: restore preview (docs/PHASE-2A-DESIGN.md, part C). A preview opens one
// backup with its own password, writes nothing, and returns metadata only.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { MASTER_PASSWORD, createVault, makeEntry } = require('./helpers');

const BACKUP_PASSWORD = 'an older backup password';
const OPEN_ERROR = 'Incorrect password, or the backup is damaged.';
const UUID = '0f8e2b7c-1a2b-4c3d-8e9f-a0b1c2d3e4f5';
const MS = 1762900000000;
const SUMMARY_KEYS = ['entryCount', 'newestUpdatedAt', 'oldestCreatedAt', 'version', 'willUpgrade'];
const MAX_VAULT_BYTES = 8 * 1024 * 1024;

const backupId = (ms = MS) => `vault-backup-${ms}-${UUID}.bak`;
const legacyId = (version, ms = MS) => `vault.json.v${version}-${ms}-${UUID}.bak`;
const sha256 = (bytes) => crypto.createHash('sha256').update(bytes).digest('hex');

// An envelope of any version holding exactly `entries`, encrypted with `password`. Uses the lowest
// iteration count the vault accepts, to keep the tests fast.
function makeEnvelope(entries, { version = 3, password = BACKUP_PASSWORD } = {}) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(entries), 'utf8'), cipher.final()]);
  key.fill(0);
  return JSON.stringify({
    version,
    kdf: 'pbkdf2-sha256',
    iterations: 100000,
    cipher: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  }, null, 2);
}

function storedEntry(overrides = {}) {
  return {
    id: crypto.randomUUID(),
    site: 'example.com',
    username: 'alice',
    password: 'secret-password',
    notes: 'private notes',
    category: 'login',
    favorite: false,
    backupCodes: [{ id: crypto.randomUUID(), code: 'code-one', used: false }],
    createdAt: '2025-01-01T00:00:00.000Z',
    updatedAt: '2025-01-01T00:00:00.000Z',
    ...overrides
  };
}

// The version 2 entry shape: the version 3 one without backup codes.
function v2Entry(overrides = {}) {
  const { backupCodes: _codes, ...entry } = storedEntry(overrides);
  return entry;
}

// Every file in the folder, name -> bytes, to prove a preview wrote, renamed and removed nothing.
async function snapshot(directory) {
  const files = {};
  for (const name of (await fs.readdir(directory)).sort()) {
    const stats = await fs.lstat(path.join(directory, name));
    files[name] = stats.isFile() ? (await fs.readFile(path.join(directory, name))).toString('base64') : 'not a file';
  }
  return files;
}

// Runs `operation` and checks that the folder is byte-identical afterwards.
async function unchanged(directory, operation) {
  const before = await snapshot(directory);
  const result = await operation();
  assert.deepEqual(await snapshot(directory), before, 'a preview must not write anything');
  return result;
}

test('a version 3 backup gives its count, dates and version, and nothing else', async (t) => {
  const { vault, directory } = await createVault(t);
  const entries = [
    storedEntry({ site: 'a.example', createdAt: '2024-03-01T10:00:00.000Z', updatedAt: '2025-11-03T09:00:00.000Z' }),
    storedEntry({ site: 'b.example', createdAt: '2023-07-15T08:30:00.000Z', updatedAt: '2024-01-01T00:00:00.000Z' }),
    storedEntry({ site: 'c.example', createdAt: '2025-02-02T00:00:00.000Z', updatedAt: '2025-02-02T00:00:00.000Z' })
  ];
  const contents = makeEnvelope(entries);
  await fs.writeFile(path.join(directory, backupId()), contents);

  const result = await unchanged(directory, () => vault.previewBackup(backupId(), BACKUP_PASSWORD));
  assert.deepEqual(Object.keys(result).sort(), ['digest', 'summary']);
  assert.deepEqual(result.summary, {
    entryCount: 3,
    newestUpdatedAt: '2025-11-03T09:00:00.000Z',
    oldestCreatedAt: '2023-07-15T08:30:00.000Z',
    version: 3,
    willUpgrade: false
  });
  assert.equal(result.digest, sha256(Buffer.from(contents)));

  const text = JSON.stringify(result);
  const salt = JSON.parse(contents).salt;
  for (const secret of ['a.example', 'alice', 'secret-password', 'private notes', 'code-one', salt, entries[0].id]) {
    assert.equal(text.includes(secret), false, `the preview must not contain ${secret}`);
  }
});

test('a backup the vault made itself previews with the master password', async (t) => {
  const { vault, directory } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example' }));
  await vault.saveEntry(makeEntry({ site: 'b.example' }));
  const made = await vault.createBackup();

  const { summary } = await unchanged(directory, () => vault.previewBackup(made, MASTER_PASSWORD));
  assert.equal(summary.entryCount, 2);
  assert.equal(summary.version, 3);
  assert.equal(summary.willUpgrade, false);
  assert.deepEqual(Object.keys(summary).sort(), SUMMARY_KEYS);
});

test('a version 2 backup is upgraded in memory only and reports it will be upgraded', async (t) => {
  const { vault, directory } = await createVault(t);
  const entries = [
    v2Entry({ site: 'a.example', createdAt: '2022-05-05T05:05:05.000Z', updatedAt: '2023-06-06T06:06:06.000Z' }),
    v2Entry({ site: 'b.example', createdAt: '2021-01-01T00:00:00.000Z', updatedAt: '2021-02-02T00:00:00.000Z' })
  ];
  for (const id of [backupId(), legacyId(2)]) {
    await fs.writeFile(path.join(directory, id), makeEnvelope(entries, { version: 2 }));
    const { summary } = await unchanged(directory, () => vault.previewBackup(id, BACKUP_PASSWORD));
    assert.deepEqual(summary, {
      entryCount: 2,
      newestUpdatedAt: '2023-06-06T06:06:06.000Z',
      oldestCreatedAt: '2021-01-01T00:00:00.000Z',
      version: 2,
      willUpgrade: true
    });
  }
});

test('a version 1 backup counts every entry, and dates only the entries that have them', async (t) => {
  const { vault, directory } = await createVault(t);
  const entries = [
    { site: 'Old', password: 'secret-two' },
    { site: 'Dated', password: 'secret-one', username: 'alice', createdAt: '2020-02-02T00:00:00.000Z', updatedAt: '2020-03-03T00:00:00.000Z' }
  ];
  await fs.writeFile(path.join(directory, legacyId(1)), makeEnvelope(entries, { version: 1 }));
  const { summary } = await unchanged(directory, () => vault.previewBackup(legacyId(1), BACKUP_PASSWORD));
  assert.deepEqual(summary, {
    entryCount: 2,
    newestUpdatedAt: '2020-03-03T00:00:00.000Z',
    oldestCreatedAt: '2020-02-02T00:00:00.000Z',
    version: 1,
    willUpgrade: true
  });

  await fs.writeFile(path.join(directory, backupId()), makeEnvelope([{ site: 'Old', password: 'pw' }], { version: 1 }));
  assert.deepEqual((await vault.previewBackup(backupId(), BACKUP_PASSWORD)).summary,
    { entryCount: 1, newestUpdatedAt: null, oldestCreatedAt: null, version: 1, willUpgrade: true });
});

test('an empty backup has no dates', async (t) => {
  const { vault, directory } = await createVault(t);
  await fs.writeFile(path.join(directory, backupId()), makeEnvelope([]));
  assert.deepEqual((await vault.previewBackup(backupId(), BACKUP_PASSWORD)).summary,
    { entryCount: 0, newestUpdatedAt: null, oldestCreatedAt: null, version: 3, willUpgrade: false });
});

test('a wrong password and tampered data give the same message and write nothing', async (t) => {
  const { vault, directory } = await createVault(t);
  const good = JSON.parse(makeEnvelope([storedEntry()]));
  await fs.writeFile(path.join(directory, backupId(MS)), JSON.stringify(good));

  const flip = (base64) => {
    const bytes = Buffer.from(base64, 'base64');
    bytes[0] ^= 1;
    return bytes.toString('base64');
  };
  await fs.writeFile(path.join(directory, backupId(MS + 1)), JSON.stringify({ ...good, tag: flip(good.tag) }));
  await fs.writeFile(path.join(directory, backupId(MS + 2)), JSON.stringify({ ...good, ciphertext: flip(good.ciphertext) }));
  await fs.writeFile(path.join(directory, backupId(MS + 3)), JSON.stringify({ ...good, iv: flip(good.iv) }));

  await unchanged(directory, async () => {
    await assert.rejects(vault.previewBackup(backupId(MS), 'not the right password'), { message: OPEN_ERROR });
    for (const ms of [MS + 1, MS + 2, MS + 3]) {
      await assert.rejects(vault.previewBackup(backupId(ms), BACKUP_PASSWORD), { message: OPEN_ERROR });
    }
  });
});

test('entries that fail validation are rejected, for every version', async (t) => {
  const { vault, directory } = await createVault(t);
  const id = crypto.randomUUID();
  const bad = {
    'v3 bad category': makeEnvelope([storedEntry({ category: 'bogus' })]),
    'v3 extra field': makeEnvelope([{ ...storedEntry(), extra: 'x' }]),
    'v3 duplicate ids': makeEnvelope([storedEntry({ id }), storedEntry({ id, site: 'other.example' })]),
    'v3 bad timestamp': makeEnvelope([storedEntry({ updatedAt: 'yesterday' })]),
    'v3 not an array': makeEnvelope({ site: 'example.com' }),
    'v2 with backup codes': makeEnvelope([storedEntry()], { version: 2 }),
    'v2 empty password': makeEnvelope([v2Entry({ password: '' })], { version: 2 }),
    'v1 unknown field': makeEnvelope([{ site: 'Old', password: 'pw', backupCodes: [] }], { version: 1 }),
    'v1 missing password': makeEnvelope([{ site: 'Old' }], { version: 1 })
  };
  let ms = MS;
  const ids = {};
  for (const [label, contents] of Object.entries(bad)) {
    ids[label] = backupId(ms++);
    await fs.writeFile(path.join(directory, ids[label]), contents);
  }
  await unchanged(directory, async () => {
    for (const label of Object.keys(bad)) {
      await assert.rejects(vault.previewBackup(ids[label], BACKUP_PASSWORD), { message: OPEN_ERROR }, label);
    }
  });
});

test('an invalid envelope, or a version that does not match a v<N> name, is rejected as invalid', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  const current = JSON.parse(await fs.readFile(vaultPath, 'utf8'));
  const files = {
    [backupId(MS)]: 'not json',
    [backupId(MS + 1)]: JSON.stringify({ ...current, version: 4 }),
    [backupId(MS + 2)]: JSON.stringify({ ...current, salt: 'not base64!' }),
    [backupId(MS + 3)]: '',
    [legacyId(2, MS + 4)]: await fs.readFile(vaultPath, 'utf8')
  };
  for (const [name, contents] of Object.entries(files)) await fs.writeFile(path.join(directory, name), contents);
  await unchanged(directory, async () => {
    for (const name of Object.keys(files)) {
      await assert.rejects(vault.previewBackup(name, MASTER_PASSWORD), { message: 'Backup file is invalid or corrupted.' }, name);
    }
  });
});

test('invalid ids and passwords are rejected before any file is read', async (t) => {
  const { vault, directory } = await createVault(t);
  await fs.writeFile(path.join(directory, backupId()), makeEnvelope([]));
  const badIds = [
    '../vault.json', 'vault.json', 'C:\\Windows\\vault-backup.bak', `..\\${backupId()}`, `sub/${backupId()}`,
    backupId().replace('0f8e', '0F8E'), `${backupId()}x`, 'x'.repeat(129), '', 42, null, undefined, {}, [backupId()]
  ];
  await unchanged(directory, async () => {
    for (const id of badIds) {
      await assert.rejects(vault.previewBackup(id, BACKUP_PASSWORD), { message: 'Invalid backup id.' }, String(id));
    }
    for (const password of ['', 'x'.repeat(1025), 42, null, undefined, {}, ['pw'], { toString: () => BACKUP_PASSWORD }]) {
      await assert.rejects(vault.previewBackup(backupId(), password), /Enter the master password for this backup/);
    }
  });
  // The limits themselves are allowed: a 1-character and a 1024-character password are tried.
  await assert.rejects(vault.previewBackup(backupId(), 'x'), { message: OPEN_ERROR });
  await assert.rejects(vault.previewBackup(backupId(), 'x'.repeat(1024)), { message: OPEN_ERROR });
});

test('a missing, too-large or non-regular file is rejected without a path in the message', async (t) => {
  const { vault, directory } = await createVault(t);
  await fs.writeFile(path.join(directory, backupId(MS)), Buffer.alloc(MAX_VAULT_BYTES + 1, 0x20));
  await fs.mkdir(path.join(directory, backupId(MS + 1)));

  await unchanged(directory, async () => {
    await assert.rejects(vault.previewBackup(backupId(MS), BACKUP_PASSWORD), { message: 'Backup file is too large.' });
    await assert.rejects(vault.previewBackup(backupId(MS + 1), BACKUP_PASSWORD), { message: 'Backup not found.' });
    await assert.rejects(vault.previewBackup(backupId(MS + 2), BACKUP_PASSWORD), { message: 'Backup not found.' });
  });
});

test('a symlink with a backup name is not followed', async (t) => {
  const { vault, vaultPath, directory } = await createVault(t);
  try {
    await fs.symlink(vaultPath, path.join(directory, backupId()), 'file');
  } catch (error) {
    if (error.code === 'EPERM') return t.skip('creating symlinks needs extra rights on this machine');
    throw error;
  }
  await assert.rejects(vault.previewBackup(backupId(), MASTER_PASSWORD), { message: 'Backup not found.' });
});

test('a preview leaves a locked vault locked', async (t) => {
  const { vault, directory } = await createVault(t);
  const made = await vault.createBackup();
  vault.lock();

  const { summary } = await unchanged(directory, () => vault.previewBackup(made, MASTER_PASSWORD));
  assert.equal(summary.entryCount, 0);
  assert.equal(vault.isUnlocked(), false);
  assert.equal(vault.key, null);
  await assert.rejects(vault.loadEntries(), /Unlock the vault first/);
});

test('a preview leaves an unlocked session and its key untouched, even when it fails', async (t) => {
  const { vault, directory } = await createVault(t);
  await vault.saveEntry(makeEntry({ site: 'a.example' }));
  await fs.writeFile(path.join(directory, backupId()), makeEnvelope([storedEntry()]));
  const key = vault.key;
  const keyBytes = Buffer.from(key);

  await vault.previewBackup(backupId(), BACKUP_PASSWORD);
  await assert.rejects(vault.previewBackup(backupId(), 'wrong password'), { message: OPEN_ERROR });

  assert.equal(vault.key, key, 'the same key object stays in use');
  assert.deepEqual(Buffer.from(vault.key), keyBytes, 'and it is not zeroed or changed');
  assert.deepEqual((await vault.loadEntries()).map((entry) => entry.site), ['a.example']);
  await vault.saveEntry(makeEntry({ site: 'b.example' }));
  assert.equal((await vault.loadEntries()).length, 2);
});

test('the derived key is zeroed after a preview, on success and on failure', async (t) => {
  const { vault, directory } = await createVault(t);
  await fs.writeFile(path.join(directory, backupId()), makeEnvelope([storedEntry()]));
  const derived = [];
  // vault.js promisifies crypto.pbkdf2 when it loads, so catch the keys at the decipher instead.
  const createDecipheriv = crypto.createDecipheriv;
  crypto.createDecipheriv = function capture(algorithm, key, iv) {
    derived.push(key);
    return createDecipheriv.call(this, algorithm, key, iv);
  };
  t.after(() => { crypto.createDecipheriv = createDecipheriv; });

  await vault.previewBackup(backupId(), BACKUP_PASSWORD);
  await assert.rejects(vault.previewBackup(backupId(), 'wrong password'), { message: OPEN_ERROR });
  assert.equal(derived.length, 2);
  derived.forEach((key) => assert.ok(key.every((byte) => byte === 0), 'key bytes must be zeroed'));
});

test('getVaultState is the SHA-256 of the vault file, or absent', async (t) => {
  const { vault, vaultPath } = await createVault(t);
  assert.equal(await vault.getVaultState(), sha256(await fs.readFile(vaultPath)));
  await vault.saveEntry(makeEntry());
  assert.equal(await vault.getVaultState(), sha256(await fs.readFile(vaultPath)));
  await fs.rm(vaultPath);
  assert.equal(await vault.getVaultState(), 'absent');
});
