const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const { registerCsvHandlers, buildVaultCsv } = require('../csv-transfer');
const { createVault, makeEntry } = require('./helpers');

const makeVault = createVault; // temp directory + unlocked vault, from test/helpers.js

// Registers the real handlers with fake dialogs. `script` decides what the "user" does:
//   openPath  - file chosen in the open dialog (null = cancelled)
//   savePath  - file chosen in the save dialog (null = cancelled)
//   answers   - the button index pressed for each message box, in order
async function fixture(t, { openPath = null, savePath = null, answers = [], beforeSave } = {}) {
  const { vault, directory } = await makeVault(t);
  const handlers = {};
  const calls = { open: 0, boxes: [], save: [], activity: 0 };
  registerCsvHandlers({
    registerVaultHandler: (channel, operation) => { handlers[channel] = operation; },
    getVault: () => vault,
    getParentWindow: () => null,
    dialog: {
      showOpenDialog: async () => {
        calls.open++;
        return openPath ? { canceled: false, filePaths: [openPath] } : { canceled: true, filePaths: [] };
      },
      showMessageBox: async (_parent, options) => {
        calls.boxes.push(options);
        return { response: answers[calls.boxes.length - 1] ?? 0 };
      },
      showSaveDialog: async (_parent, options) => {
        calls.save.push(options);
        await beforeSave?.(vault);
        return savePath ? { canceled: false, filePath: savePath } : { canceled: true };
      }
    },
    getDefaultDirectory: () => path.join(directory, 'Downloads'),
    onActivity: () => { calls.activity++; }
  });
  return {
    vault, directory, calls,
    importCsv: () => handlers['vault:import-csv'](),
    exportCsv: () => handlers['vault:export-csv']()
  };
}

const SAMPLE = 'name,url,username,password\nGitHub,https://github.com,alice,Sup3r-Secret!\nBank,https://bank.example,bob,An0ther-Secret!\n';
const backups = async (directory) => (await fs.readdir(directory)).filter((name) => name.endsWith('.bak'));

// ---------------------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------------------

async function importFixture(t, { csv, response = 1, pick = true }) {
  const f = await fixture(t, { answers: [response] });
  const csvPath = path.join(f.directory, 'passwords.csv');
  if (csv !== undefined) await fs.writeFile(csvPath, csv);
  // The shared fixture has no file to open until we know the directory, so point it now.
  const original = f.calls;
  return { ...f, csvPath, original, run: () => f.importCsv(), setPick: () => {} };
}

// A second helper that fixes the open-dialog path up front (the directory is created inside).
async function importCase(t, { csv, response = 1, pick = true }) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'csv-in-'));
  t.after(() => fs.rm(dir, { recursive: true, force: true }));
  const csvPath = path.join(dir, 'passwords.csv');
  if (csv !== undefined) await fs.writeFile(csvPath, csv);
  const f = await fixture(t, { openPath: pick ? csvPath : null, answers: [response] });
  return { ...f, csvPath, run: f.importCsv };
}

test('import: keep the CSV, backs up first, returns no secrets', async (t) => {
  const f = await importCase(t, { csv: SAMPLE, response: 1 });
  const vaultBefore = await fs.readFile(path.join(f.directory, 'vault.json'), 'utf8');

  const result = await f.run();
  assert.equal(result.success, true);
  assert.equal(result.added, 2);
  assert.equal(result.csvDeleted, false);
  await fs.access(f.csvPath);

  assert.deepEqual(await backups(f.directory), [result.backupName]);
  assert.equal(await fs.readFile(path.join(f.directory, result.backupName), 'utf8'), vaultBefore);
  assert.equal((await f.vault.loadEntries()).length, 2);
  assert.ok(f.calls.activity >= 1);
  assert.ok(!JSON.stringify(result).includes('Secret!'));
  assert.ok(!JSON.stringify(f.calls.boxes).includes('Secret!'));
});

test('import: delete the CSV only after the import succeeded', async (t) => {
  const f = await importCase(t, { csv: SAMPLE, response: 0 });
  const result = await f.run();
  assert.equal(result.csvDeleted, true);
  await assert.rejects(fs.access(f.csvPath));
  assert.equal((await f.vault.loadEntries()).length, 2);
});

test('import: cancelling at either dialog changes nothing', async (t) => {
  const declined = await importCase(t, { csv: SAMPLE, response: 2 });
  assert.deepEqual(await declined.run(), { success: false, cancelled: true });
  assert.equal((await declined.vault.loadEntries()).length, 0);
  assert.deepEqual(await backups(declined.directory), []);
  await fs.access(declined.csvPath);

  const noFile = await importCase(t, { pick: false });
  assert.deepEqual(await noFile.run(), { success: false, cancelled: true });
  assert.equal(noFile.calls.boxes.length, 0);
});

test('import: a bad file, a locked vault and a repeat import are handled', async (t) => {
  const bad = await importCase(t, { csv: 'just,some,numbers\n1,2,3\n' });
  await assert.rejects(bad.run(), /needed columns/);
  assert.equal(bad.calls.boxes.length, 0);

  const locked = await importCase(t, { csv: SAMPLE });
  locked.vault.lock();
  await assert.rejects(locked.run(), /Unlock the vault first/);
  assert.equal(locked.calls.open, 0);

  const again = await importCase(t, { csv: SAMPLE, response: 1 });
  await again.run();
  const second = await again.run();
  assert.equal(second.added, 0);
  assert.equal(second.duplicates, 2);
  assert.equal(again.calls.boxes.length, 1); // nothing to import the second time -> no confirmation
  assert.equal((await again.vault.loadEntries()).length, 2);
});

test('import: skipped rows and ignored columns are reported without file content', async (t) => {
  const f = await importCase(t, { csv: 'name,username,password,totp\nGood,a,pw1,JBSWY3DPEHPK3PXP\nNoPassword,b,,\n', response: 1 });
  const result = await f.run();
  assert.equal(result.added, 1);
  assert.deepEqual(result.problems, [{ row: 3, reason: 'No password (secure notes and passkeys are skipped).' }]);
  assert.equal(result.problemCount, 1);
  assert.deepEqual(result.ignoredColumns, ['totp']);
  assert.match(f.calls.boxes[0].detail, /Columns that are not imported: totp/);
  assert.ok(!JSON.stringify(result).includes('JBSWY3DPEHPK3PXP'));
});

// ---------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------

async function seed(vault) {
  await vault.saveEntry(makeEntry({
    site: 'github.com', username: 'alice', password: 'Sup3r-Secret!', notes: 'n', category: 'work', favorite: true,
    backupCodes: ['AAAA-1111', 'BBBB-2222']
  }));
  await vault.saveEntry(makeEntry({ site: 'My Bank', username: 'bob', password: '=An0ther,Secret"', category: 'finance' }));
  // Mark one code as used: it is left out of the export.
  const [github] = (await vault.loadEntries()).filter((e) => e.site === 'github.com');
  await vault.setBackupCodeUsed(github.id, github.backupCodes[1].id, true);
}

test('export: warns, asks where to save, then writes every entry', async (t) => {
  const out = await fs.mkdtemp(path.join(os.tmpdir(), 'csv-out-'));
  t.after(() => fs.rm(out, { recursive: true, force: true }));
  const target = path.join(out, 'mine.csv');
  const f = await fixture(t, { savePath: target, answers: [0] });
  await seed(f.vault);

  const result = await f.exportCsv();
  assert.deepEqual(result, { success: true, count: 2, fileName: 'mine.csv' });

  assert.equal(f.calls.boxes.length, 1);
  assert.match(f.calls.boxes[0].message, /Export 2 entries/);
  assert.match(f.calls.boxes[0].detail, /plain text/);
  assert.equal(f.calls.boxes[0].defaultId, 1, 'Cancel must be the default button');
  assert.match(f.calls.save[0].defaultPath, /Downloads[\\/]vlautr-export-\d{4}-\d{2}-\d{2}\.csv$/);

  const written = await fs.readFile(target, 'utf8');
  assert.equal(written, buildVaultCsv(await f.vault.loadEntries()));
  assert.ok(written.includes('Sup3r-Secret!'));
  assert.ok(written.includes('AAAA-1111') && !written.includes('BBBB-2222'), 'only the unused backup code is exported');
  if (process.platform !== 'win32') assert.equal((await fs.stat(target)).mode & 0o777, 0o600);

  // Only a count and a file name go back to the page, and no dialog quotes a secret.
  assert.ok(!JSON.stringify(result).includes('Secret'));
  assert.ok(!JSON.stringify([f.calls.boxes, f.calls.save]).includes('Secret'));
  assert.ok(f.calls.activity >= 1);
});

test('export: cancelling at the warning or the save dialog writes nothing', async (t) => {
  const out = await fs.mkdtemp(path.join(os.tmpdir(), 'csv-out-'));
  t.after(() => fs.rm(out, { recursive: true, force: true }));
  const target = path.join(out, 'never.csv');

  const atWarning = await fixture(t, { savePath: target, answers: [1] });
  await seed(atWarning.vault);
  assert.deepEqual(await atWarning.exportCsv(), { success: false, cancelled: true });
  assert.equal(atWarning.calls.save.length, 0, 'no save dialog after declining the warning');

  const atSave = await fixture(t, { savePath: null, answers: [0] });
  await seed(atSave.vault);
  assert.deepEqual(await atSave.exportCsv(), { success: false, cancelled: true });

  assert.deepEqual(await fs.readdir(out), []);
});

test('export: a cloud-synced folder needs a second confirmation', async (t) => {
  const out = await fs.mkdtemp(path.join(os.tmpdir(), 'csv-out-'));
  t.after(() => fs.rm(out, { recursive: true, force: true }));
  const synced = path.join(out, 'OneDrive', 'Documents');
  await fs.mkdir(synced, { recursive: true });
  const target = path.join(synced, 'passwords.csv');

  const declined = await fixture(t, { savePath: target, answers: [0, 1] });
  await seed(declined.vault);
  assert.deepEqual(await declined.exportCsv(), { success: false, cancelled: true });
  assert.equal(declined.calls.boxes.length, 2);
  assert.match(declined.calls.boxes[1].message, /synced to the cloud/);
  await assert.rejects(fs.access(target));

  const accepted = await fixture(t, { savePath: target, answers: [0, 0] });
  await seed(accepted.vault);
  assert.equal((await accepted.exportCsv()).success, true);
  await fs.access(target);
});

test('export: an empty or locked vault is refused before any dialog', async (t) => {
  const empty = await fixture(t, { savePath: '/never.csv', answers: [0] });
  await assert.rejects(empty.exportCsv(), /no entries/);
  assert.equal(empty.calls.boxes.length, 0);

  const locked = await fixture(t, { savePath: '/never.csv', answers: [0] });
  await seed(locked.vault);
  locked.vault.lock();
  await assert.rejects(locked.exportCsv(), /Unlock the vault first/);
  assert.equal(locked.calls.boxes.length, 0);
});

test('export: if the vault locks while a dialog is open, nothing is written', async (t) => {
  const out = await fs.mkdtemp(path.join(os.tmpdir(), 'csv-out-'));
  t.after(() => fs.rm(out, { recursive: true, force: true }));
  const target = path.join(out, 'late.csv');
  const f = await fixture(t, { savePath: target, answers: [0], beforeSave: (vault) => vault.lock() });
  await seed(f.vault);

  await assert.rejects(f.exportCsv(), /Unlock the vault first/);
  assert.deepEqual(await fs.readdir(out), []);
});

test('round trip through the handlers: export one vault, import into another', async (t) => {
  const out = await fs.mkdtemp(path.join(os.tmpdir(), 'csv-out-'));
  t.after(() => fs.rm(out, { recursive: true, force: true }));
  const target = path.join(out, 'transfer.csv');

  const source = await fixture(t, { savePath: target, answers: [0] });
  await seed(source.vault);
  await source.exportCsv();

  const destination = await fixture(t, { openPath: target, answers: [1] });
  const result = await destination.importCsv();
  assert.equal(result.added, 2);
  assert.equal(result.problemCount, 0);
  assert.deepEqual(result.ignoredColumns, []);

  const strip = ({ site, username, password, notes, category, favorite, backupCodes }) => ({
    site, username, password, notes, category, favorite, backupCodes: backupCodes.filter((c) => !c.used).map((c) => c.code)
  });
  const bySite = (a, b) => a.site.localeCompare(b.site);
  assert.deepEqual(
    (await destination.vault.loadEntries()).map(strip).sort(bySite),
    (await source.vault.loadEntries()).map(strip).sort(bySite)
  );
});

test('file errors are reported without the file path', async (t) => {
  const missing = await importCase(t, {}); // the open dialog points at a file that does not exist
  await assert.rejects(missing.run(), (error) => error.message === 'The file or folder could not be found.' && !error.message.includes(missing.directory));

  const out = await fs.mkdtemp(path.join(os.tmpdir(), 'csv-out-'));
  t.after(() => fs.rm(out, { recursive: true, force: true }));
  const impossible = await fixture(t, { savePath: path.join(out, 'no-such-folder', 'x.csv'), answers: [0] });
  await seed(impossible.vault);
  await assert.rejects(impossible.exportCsv(), (error) => error.message === 'The file or folder could not be found.' && !error.message.includes(out));
});
