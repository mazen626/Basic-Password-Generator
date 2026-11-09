'use strict';
const fs = require('node:fs/promises');
const path = require('node:path');
const { MAX_CSV_BYTES, parseVaultCsv, previewImport, importEntries } = require('./csv-import');
const { buildVaultCsv, exportFileName } = require('./csv-export');
const MAX_PROBLEMS_SENT = 50;
const count = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const FILE_ERRORS = {
  ENOENT: 'The file or folder could not be found.',
  EACCES: 'Windows did not allow access to that file.',
  EPERM: 'Windows did not allow access to that file.',
  EBUSY: 'The file is in use by another program.',
  EISDIR: 'Choose a file, not a folder.',
  ENOSPC: 'There is not enough free disk space.'
};

async function fileOperation(operation, fallback) {
  try {
    return await operation();
  } catch (error) {
    if (typeof error?.code === 'string' && error.code.startsWith('E')) throw new Error(FILE_ERRORS[error.code] ?? fallback);
    throw error;
  }
}

const IMPORT_AND_DELETE = 0;
const IMPORT_CANCEL = 2;

async function readAndParse(filePath) {
  const stats = await fileOperation(() => fs.stat(filePath), 'Could not open that file.');
  if (!stats.isFile()) throw new Error('Choose a regular file.');
  if (stats.size > MAX_CSV_BYTES) throw new Error('That file is too large to be a password export (limit 5 MB).');

  const buffer = await fileOperation(() => fs.readFile(filePath), 'Could not read that file.');
  try {
    return parseVaultCsv(buffer);
  } finally {
    buffer.fill(0); 
  }
}

function describeImportPlan(plan, parsed) {
  const lines = [];
  if (plan.duplicates) lines.push(`${count(plan.duplicates, 'entry is', 'entries are')} already in your vault (skipped).`);
  if (plan.renamed) lines.push(`${count(plan.renamed, 'entry shares', 'entries share')} a site name with another entry, so the username is added to the name, for example "github.com (alice)".`);
  if (parsed.problems.length) lines.push(`${count(parsed.problems.length, 'row cannot', 'rows cannot')} be imported. They are listed after the import.`);
  if (parsed.ignoredColumns.length) lines.push(`Columns that are not imported: ${parsed.ignoredColumns.join(', ')}.`);
  lines.push(
    '',
    'An encrypted backup of your vault is made first.',
    'The CSV file holds your passwords as plain text, so deleting it is the safest choice. Deleting removes the file but is not a secure wipe.'
  );
  return lines.join('\n');
}

function registerImport({ registerVaultHandler, getVault, getParentWindow, dialog, onActivity }) {
  registerVaultHandler('vault:import-csv', async () => {
    const vault = getVault();
    if (!vault?.isUnlocked()) throw new Error('Unlock the vault first.');
    const parent = getParentWindow();

    const picked = await dialog.showOpenDialog(parent, {
      title: 'Choose the CSV file to import',
      properties: ['openFile'],
      filters: [{ name: 'CSV files', extensions: ['csv'] }, { name: 'All files', extensions: ['*'] }]
    });
    if (picked.canceled || picked.filePaths.length === 0) return { success: false, cancelled: true };
    const filePath = picked.filePaths[0];

    const parsed = await readAndParse(filePath);
    const report = {
      problems: parsed.problems.slice(0, MAX_PROBLEMS_SENT),
      problemCount: parsed.problems.length,
      ignoredColumns: parsed.ignoredColumns
    };

    const plan = await previewImport(vault, parsed.entries);
    if (plan.toAdd === 0) {
      onActivity();
      return { success: true, added: 0, duplicates: plan.duplicates, renamed: 0, csvDeleted: false, ...report };
    }

    const choice = await dialog.showMessageBox(parent, {
      type: 'question',
      buttons: ['Import and delete the CSV file', 'Import and keep the CSV file', 'Cancel'],
      defaultId: IMPORT_CANCEL,
      cancelId: IMPORT_CANCEL,
      noLink: true,
      title: 'Import passwords',
      message: `Add ${count(plan.toAdd, 'entry', 'entries')} to your vault from "${path.basename(filePath)}"?`,
      detail: describeImportPlan(plan, parsed)
    });
    if (choice.response === IMPORT_CANCEL) return { success: false, cancelled: true };

    const backupName = await vault.createBackup();
    const result = await importEntries(vault, parsed.entries);

    let csvDeleted = false;
    if (choice.response === IMPORT_AND_DELETE) {
      try {
        await fs.rm(filePath);
        csvDeleted = true;
      } catch {}
    }

    onActivity();
    return { success: true, ...result, backupName, csvDeleted, ...report };
  });
}

const EXPORT_CONTINUE = 0;
const EXPORT_CANCEL = 1;
const SYNCED_FOLDER = /[\\/](onedrive|dropbox|google ?drive|icloud ?drive|box sync)[^\\/]*[\\/]/i;

function registerExport({ registerVaultHandler, getVault, getParentWindow, dialog, getDefaultDirectory, onActivity }) {
  registerVaultHandler('vault:export-csv', async () => {
    const vault = getVault();
    if (!vault?.isUnlocked()) throw new Error('Unlock the vault first.');
    const parent = getParentWindow();

    const total = (await vault.loadEntries()).length;
    if (total === 0) throw new Error('Your vault has no entries to export.');
    const warning = await dialog.showMessageBox(parent, {
      type: 'warning',
      buttons: ['Choose where to save...', 'Cancel'],
      defaultId: EXPORT_CANCEL,
      cancelId: EXPORT_CANCEL,
      noLink: true,
      title: 'Export passwords',
      message: `Export ${count(total, 'entry', 'entries')} to a CSV file?`,
      detail: [
        'The file will hold every password as plain text, with no encryption. Anyone who can open it can read them.',
        '',
        'Save it somewhere private (not a OneDrive, Google Drive or Dropbox folder), import it into your other password manager rather than opening it in Excel, and delete it as soon as you are done.'
      ].join('\n')
    });
    if (warning.response !== EXPORT_CONTINUE) return { success: false, cancelled: true };
    const target = await dialog.showSaveDialog(parent, {
      title: 'Save the exported CSV file',
      defaultPath: path.join(getDefaultDirectory?.() ?? '', exportFileName()),
      filters: [{ name: 'CSV files', extensions: ['csv'] }],
      properties: ['showOverwriteConfirmation']
    });
    if (target.canceled || !target.filePath) return { success: false, cancelled: true };
    const filePath = target.filePath;

    if (SYNCED_FOLDER.test(filePath)) {
      const synced = await dialog.showMessageBox(parent, {
        type: 'warning',
        buttons: ['Save here anyway', 'Cancel'],
        defaultId: EXPORT_CANCEL,
        cancelId: EXPORT_CANCEL,
        noLink: true,
        title: 'Cloud-synced folder',
        message: 'This folder looks like it is synced to the cloud.',
        detail: 'A plain-text password file would be uploaded, and old copies can stay in the cloud (or its version history) after you delete the file. Choose a folder that only exists on this computer.'
      });
      if (synced.response !== EXPORT_CONTINUE) return { success: false, cancelled: true };
    }
    const entries = await vault.loadEntries();
    const data = Buffer.from(buildVaultCsv(entries), 'utf8');
    try {
      await fileOperation(() => fs.writeFile(filePath, data, { mode: 0o600 }), 'Could not save the file there.');
    } finally {
      data.fill(0);
    }

    onActivity();
    return { success: true, count: entries.length, fileName: path.basename(filePath) };
  });
}

function registerCsvHandlers(deps) {
  registerImport(deps);
  registerExport(deps);
}

module.exports = { registerCsvHandlers };
