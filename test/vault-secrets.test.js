const assert = require('node:assert/strict');
const test = require('node:test');
const { MASTER_PASSWORD, createVault, makeEntry } = require('./helpers');

const MISSING_ID = '00000000-0000-4000-8000-000000000000';

async function saveOne(vault, overrides = {}) {
  await vault.saveEntry(makeEntry(overrides));
  return (await vault.loadEntries()).find((entry) => entry.site === (overrides.site ?? 'example.com'));
}

test('entry summaries hold everything except the password and code values', async (t) => {
  const { vault } = await createVault(t);
  const saved = await saveOne(vault, { notes: 'a note', favorite: true, backupCodes: ['one', 'two', 'three'] });
  await vault.setBackupCodeUsed(saved.id, saved.backupCodes[1].id, true);

  const [summary] = await vault.loadEntrySummaries();
  assert.deepEqual(summary, {
    id: saved.id,
    site: saved.site,
    username: saved.username,
    notes: 'a note',
    category: saved.category,
    favorite: true,
    createdAt: saved.createdAt,
    updatedAt: saved.updatedAt,
    hasPassword: true,
    backupCodes: { total: 3, unused: 2 }
  });
});

test('one entry\'s password and codes can be read by ID, as copies', async (t) => {
  const { vault } = await createVault(t);
  const saved = await saveOne(vault, { password: 'pw-one', backupCodes: ['aaa'] });

  assert.equal(await vault.getEntryPassword(saved.id), 'pw-one');
  assert.equal(await vault.getEntrySite(saved.id), 'example.com');
  const codes = await vault.getBackupCodes(saved.id);
  assert.deepEqual(codes, [{ id: saved.backupCodes[0].id, code: 'aaa', used: false }]);

  codes[0].used = true;
  codes[0].code = 'changed';
  assert.deepEqual(await vault.getBackupCodes(saved.id), [{ id: saved.backupCodes[0].id, code: 'aaa', used: false }]);
});

test('reading secrets by ID rejects bad IDs, missing entries and a locked vault', async (t) => {
  const { vault } = await createVault(t);
  const saved = await saveOne(vault);

  for (const read of ['getEntryPassword', 'getBackupCodes', 'getEntrySite']) {
    await assert.rejects(vault[read]('not-an-id'), /Invalid entry id/);
    await assert.rejects(vault[read](undefined), /Invalid entry id/);
    await assert.rejects(vault[read](MISSING_ID), /Entry not found/);
  }
  vault.lock();
  for (const read of ['getEntryPassword', 'getBackupCodes', 'getEntrySite', 'loadEntrySummaries']) {
    await assert.rejects(vault[read](saved.id), /Unlock the vault first/);
  }
});

test('an update without a password keeps it, and keeps updatedAt', async (t) => {
  const { vault } = await createVault(t);
  const saved = await saveOne(vault, { password: 'pw-keep' });

  const { password: _omitted, ...update } = makeEntry({ notes: 'edited' });
  await vault.updateEntry(saved.id, update);

  const [after] = await vault.loadEntries();
  assert.equal(after.password, 'pw-keep');
  assert.equal(after.notes, 'edited');
  assert.equal(after.updatedAt, saved.updatedAt);
});

test('an update without backup codes keeps them, with their used state', async (t) => {
  const { vault } = await createVault(t);
  const saved = await saveOne(vault, { backupCodes: ['aaa', 'bbb'] });
  await vault.setBackupCodeUsed(saved.id, saved.backupCodes[0].id, true);

  const { backupCodes: _omitted, ...update } = makeEntry({ username: 'renamed' });
  await vault.updateEntry(saved.id, update);

  const [after] = await vault.loadEntries();
  assert.deepEqual(after.backupCodes, [{ ...saved.backupCodes[0], used: true }, saved.backupCodes[1]]);
  assert.equal(after.username, 'renamed');
});

test('an update that sends a new password still changes it and updatedAt', async (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: Date.parse('2026-01-01T00:00:00.000Z') });
  const { vault } = await createVault(t);
  const saved = await saveOne(vault, { password: 'pw-old' });
  t.mock.timers.tick(60 * 1000);

  await vault.updateEntry(saved.id, makeEntry({ password: 'pw-new' }));
  const [after] = await vault.loadEntries();
  assert.equal(after.password, 'pw-new');
  assert.notEqual(after.updatedAt, saved.updatedAt);
});

test('an update that sends an empty or undefined password is rejected, not treated as "keep"', async (t) => {
  const { vault } = await createVault(t);
  const saved = await saveOne(vault, { password: 'pw-keep' });

  await assert.rejects(vault.updateEntry(saved.id, makeEntry({ password: '' })), /Password must contain/);
  await assert.rejects(vault.updateEntry(saved.id, makeEntry({ password: undefined })), /Password must contain/);
  await assert.rejects(vault.updateEntry(saved.id, makeEntry({ backupCodes: undefined })), /backup codes/);
  await assert.rejects(vault.updateEntry(saved.id, null), /Entry must include/);
  await assert.rejects(vault.updateEntry(saved.id, ['site']), /Entry must include/);

  const { password: _p, ...withoutPassword } = makeEntry();
  await assert.rejects(vault.updateEntry(saved.id, { ...withoutPassword, site: '' }), /Site must contain/);
  assert.equal(await vault.getEntryPassword(saved.id), 'pw-keep');
});

test('new entries still require a password and a code list', async (t) => {
  const { vault } = await createVault(t);
  const { password: _p, ...withoutPassword } = makeEntry();
  const { backupCodes: _c, ...withoutCodes } = makeEntry();
  await assert.rejects(vault.saveEntry(withoutPassword), /Entry must include/);
  await assert.rejects(vault.saveEntry(withoutCodes), /Entry must include/);
  vault.lock();
  await vault.unlock(MASTER_PASSWORD);
  assert.deepEqual(await vault.loadEntries(), []);
});
