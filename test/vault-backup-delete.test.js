// Phase 2A milestone 2A.4: manual backup cleanup in the vault layer (docs/PHASE-2A-DESIGN.md,
// part E). The IPC side (dialog, frame checks, lock during the dialog) is in ipc-handlers.test.js.
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const test = require('node:test');
const { createVault } = require('./helpers');

const MS = 1762900000000;
const uuid = (n) => `0f8e2b7c-1a2b-4c3d-8e9f-${String(n).padStart(12, '0')}`;
const name = {
  backup: (n) => `vault-backup-${MS + n}-${uuid(n)}.bak`,
  restore: (n) => `vault-before-restore-${MS + n}-${uuid(n)}.bak`
};
const OTHER_SALT = crypto.randomBytes(16).toString('base64');

// Writes a backup: a copy of the current vault (hint "current"), the same with another salt
// ("other"), or garbage ("invalid").
async function put(fixture, id, flavor = 'current') {
  const text = await fs.readFile(fixture.vaultPath, 'utf8');
  let contents = text;
  if (flavor === 'other') contents = JSON.stringify({ ...JSON.parse(text), salt: OTHER_SALT });
  if (flavor === 'invalid') contents = 'not a vault';
  await fs.writeFile(path.join(fixture.directory, id), contents);
  return id;
}

const exists = (fixture, id) => fs.access(path.join(fixture.directory, id)).then(() => true, () => false);
const listing = async (fixture) => (await fs.readdir(fixture.directory)).sort();

test('deleting backups needs an unlocked vault and touches nothing otherwise', async (t) => {
  const fixture = await createVault(t);
  const a = await put(fixture, name.backup(1), 'other');
  await put(fixture, name.backup(2), 'other');
  fixture.vault.lock();
  await assert.rejects(fixture.vault.deleteBackups([a]), { message: 'Unlock the vault first.' });
  assert.equal(await exists(fixture, a), true);
});

test('ids must be 1 to 1000 unique valid backup names, or nothing is touched', async (t) => {
  const fixture = await createVault(t);
  const a = await put(fixture, name.backup(1), 'other');
  const before = await listing(fixture);
  const bad = [
    undefined, 'x', [], [a, a], [5], [a, 'vault.json'], ['..\\vault.json'], [`C:\\${a}`], [`sub/${a}`],
    [a.toUpperCase()], Array.from({ length: 1001 }, (_, i) => name.backup(i))
  ];
  for (const ids of bad) await assert.rejects(fixture.vault.deleteBackups(ids), /different backups|Invalid backup id/);
  assert.deepEqual(await listing(fixture), before);
});

test('the newest valid backup is kept and reported, and older ones are deleted', async (t) => {
  const fixture = await createVault(t);
  const old = await put(fixture, name.backup(1), 'other');
  const mid = await put(fixture, name.backup(2), 'other');
  const newest = await put(fixture, name.backup(3), 'other');
  await put(fixture, name.backup(0), 'current'); // keeps the "current" guard off the others
  const result = await fixture.vault.deleteBackups([old, mid, newest]);
  assert.deepEqual(result.deleted, [old, mid]);
  assert.deepEqual(result.kept, [{ id: newest, reason: 'newest valid backup' }]);
});

test('the only valid backup is kept, and invalid and too-large files are deletable', async (t) => {
  const fixture = await createVault(t);
  const only = await put(fixture, name.backup(5), 'other');
  const junk = await put(fixture, name.backup(6), 'invalid');
  const large = path.join(fixture.directory, name.backup(7));
  await fs.writeFile(large, '');
  await fs.truncate(large, 8 * 1024 * 1024 + 1);
  const result = await fixture.vault.deleteBackups([only, junk, name.backup(7)]);
  assert.deepEqual(result.deleted, [junk, name.backup(7)]);
  assert.deepEqual(result.kept, [{ id: only, reason: 'only valid backup' }]);
  assert.equal(await exists(fixture, only), true);
});

test('deleting every backup always leaves at least one valid backup', async (t) => {
  const fixture = await createVault(t);
  const ids = [];
  for (let n = 1; n <= 4; n += 1) ids.push(await put(fixture, name.backup(n), n % 2 ? 'other' : 'current'));
  ids.push(await put(fixture, name.backup(9), 'invalid'));
  const result = await fixture.vault.deleteBackups(ids);
  const left = (await fixture.vault.listBackups()).filter((item) => item.status === 'valid');
  assert.ok(left.length >= 1);
  assert.equal(result.deleted.includes(name.backup(9)), true);
  assert.equal(result.kept.length + result.deleted.length, ids.length);
});

test('the newest valid backup that opens with the current password is kept, even when newer others exist', async (t) => {
  const fixture = await createVault(t);
  const current = await put(fixture, name.backup(1), 'current');
  const oldCurrent = await put(fixture, name.backup(0), 'current');
  const newerOther = await put(fixture, name.backup(2), 'other');
  const newestOther = await put(fixture, name.backup(3), 'other');
  const result = await fixture.vault.deleteBackups([current, oldCurrent, newerOther, newestOther]);
  assert.deepEqual(result.deleted.sort(), [oldCurrent, newerOther].sort());
  assert.deepEqual(result.kept, [
    { id: current, reason: 'newest backup that opens with the current password' },
    { id: newestOther, reason: 'newest valid backup' }
  ]);
});

test('the newest pre-restore backup is kept, preferring a valid one over a newer invalid one', async (t) => {
  const fixture = await createVault(t);
  await put(fixture, name.backup(1), 'other');
  await put(fixture, name.backup(50), 'other');
  const oldRestore = await put(fixture, name.restore(10), 'other');
  const validRestore = await put(fixture, name.restore(20), 'other');
  const invalidRestore = await put(fixture, name.restore(30), 'invalid');
  let result = await fixture.vault.deleteBackups([oldRestore, validRestore, invalidRestore]);
  assert.deepEqual(result.deleted.sort(), [oldRestore, invalidRestore].sort());
  assert.deepEqual(result.kept, [{ id: validRestore, reason: 'newest pre-restore backup' }]);

  // With no valid pre-restore backup, the newest pre-restore file of any status is kept.
  const lone = await createVault(t);
  await put(lone, name.backup(1), 'other');
  await put(lone, name.backup(2), 'other');
  const a = await put(lone, name.restore(10), 'invalid');
  const b = await put(lone, name.restore(20), 'invalid');
  result = await lone.vault.deleteBackups([a, b]);
  assert.deepEqual(result.deleted, [a]);
  assert.deepEqual(result.kept, [{ id: b, reason: 'newest pre-restore backup' }]);
});

test('requesting every guarded backup at once still keeps all of them', async (t) => {
  const fixture = await createVault(t);
  const newest = await put(fixture, name.backup(9), 'other');
  const current = await put(fixture, name.backup(2), 'current');
  const restore = await put(fixture, name.restore(1), 'other');
  const result = await fixture.vault.deleteBackups([newest, current, restore]);
  assert.deepEqual(result.deleted, []);
  assert.equal(result.kept.length, 3);
  for (const id of [newest, current, restore]) assert.equal(await exists(fixture, id), true);
});

test('guards use a full scan: a protected backup beyond the 1,000-item display cap is kept', async (t) => {
  const fixture = await createVault(t);
  // The older "current" backup sorts after 1,001 newer valid ones, past the display cap.
  const current = await put(fixture, name.backup(1), 'current');
  for (let n = 2; n <= 1002; n += 1) await put(fixture, name.backup(n), 'other');
  const junk = await put(fixture, name.backup(2000), 'invalid');
  const scan = await fixture.vault.listBackups();
  assert.ok(scan.findIndex((item) => item.id === current) >= 1000, 'the protected backup is beyond position 1000');

  const result = await fixture.vault.deleteBackups([current, junk]);
  assert.deepEqual(result.deleted, [junk]);
  assert.deepEqual(result.kept, [{ id: current, reason: 'newest backup that opens with the current password' }]);
  assert.equal(await exists(fixture, current), true);
});

test('a requested backup that vanished is reported as kept, and the others still go', async (t) => {
  const fixture = await createVault(t);
  await put(fixture, name.backup(9), 'other');
  const gone = await put(fixture, name.backup(1), 'invalid');
  const stays = await put(fixture, name.backup(2), 'invalid');
  await fs.rm(path.join(fixture.directory, gone));
  const result = await fixture.vault.deleteBackups([gone, stays]);
  assert.deepEqual(result.deleted, [stays]);
  assert.deepEqual(result.kept, [{ id: gone, reason: 'no longer exists' }]);
});

test('a folder or junction named like a backup is never deleted', async (t) => {
  const fixture = await createVault(t);
  await put(fixture, name.backup(9), 'other');
  const target = path.join(fixture.directory, 'elsewhere');
  await fs.mkdir(target);
  await fs.writeFile(path.join(target, 'keep.txt'), 'x');
  const folder = name.backup(1);
  const junction = name.backup(2);
  await fs.mkdir(path.join(fixture.directory, folder));
  await fs.writeFile(path.join(fixture.directory, folder, 'inside.txt'), 'x');
  await fs.symlink(target, path.join(fixture.directory, junction), 'junction');
  const result = await fixture.vault.deleteBackups([folder, junction]);
  assert.deepEqual(result.deleted, []);
  assert.deepEqual(result.kept.map((item) => item.reason), ['no longer exists', 'no longer exists']);
  assert.equal(await exists(fixture, path.join(folder, 'inside.txt')), true);
  assert.equal(await exists(fixture, path.join('elsewhere', 'keep.txt')), true);
  assert.equal(await exists(fixture, junction), true);
});

test('a file that cannot be deleted is reported as kept without a path, and the rest go on', async (t) => {
  const fixture = await createVault(t);
  await put(fixture, name.backup(9), 'other');
  const a = await put(fixture, name.backup(1), 'invalid');
  const b = await put(fixture, name.backup(2), 'invalid');
  const real = fs.unlink;
  t.mock.method(fs, 'unlink', async (target) => {
    if (target.endsWith(a)) throw Object.assign(new Error(`EPERM ${target}`), { code: 'EPERM' });
    return real(target);
  });
  const result = await fixture.vault.deleteBackups([a, b]);
  assert.deepEqual(result, { deleted: [b], kept: [{ id: a, reason: 'could not be deleted' }] });
  assert.equal(JSON.stringify(result).includes(fixture.directory), false);
});

test('vault.json and unrelated files are never touched', async (t) => {
  const fixture = await createVault(t);
  await fs.writeFile(path.join(fixture.directory, 'notes.bak'), 'x');
  const before = await fs.readFile(fixture.vaultPath);
  await put(fixture, name.backup(9), 'other');
  const junk = await put(fixture, name.backup(1), 'invalid');
  await fixture.vault.deleteBackups([junk]);
  assert.deepEqual(await fs.readFile(fixture.vaultPath), before);
  assert.equal(await exists(fixture, 'notes.bak'), true);
});
