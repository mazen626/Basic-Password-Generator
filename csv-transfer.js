'use strict';

// CSV import and export for the password vault, all in one file.
//
//   PART 1  Import logic   Pure logic: bytes -> entries -> vault. No Electron.
//   PART 2  Export logic   Pure logic: entries -> CSV text. No Electron.
//   PART 3  Electron side  File pickers, confirmations and the IPC handlers (used by main.js).
//
// The page side (the File menu items and the results window) cannot live here: it runs in the
// sandboxed page with no Node.js, so it stays in csv-ui.js.

const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { domainToUnicode } = require('node:url');
const PasswordVault = require('./vault');
const { parseBackupCodes } = require('./backup-codes');

// =======================================================================================
// PART 1: IMPORT
// =======================================================================================

// CSV import for the password vault.
//
// This part is pure logic: no Electron, no dialogs, no file paths. It works on the bytes of
// the file (a Buffer) and on a PasswordVault instance, which keeps it easy to test.
//
// The flow is:   bytes -> text -> rows -> entries      (parseVaultCsv)
//                entries + vault        -> merge plan   (planImport)
//                entries -> vault, ONE atomic write     (importEntries)

const { MAX_ENTRIES, MAX_SITE_LENGTH } = PasswordVault.LIMITS;
const MAX_CSV_BYTES = 5 * 1024 * 1024;
const MAX_TAG_LENGTH = 40;
const DELIMITERS = [',', ';', '\t'];
const TRUTHY = new Set(['1', 'true', 'yes', 'y', 'x']);

// ---------------------------------------------------------------------------------------
// 1. Bytes -> text
// ---------------------------------------------------------------------------------------

function decodeText(buffer) {
  if (buffer.length > MAX_CSV_BYTES) {
    throw new Error('That file is too large to be a password export (limit 5 MB).');
  }

  // A byte-order mark says how the file is encoded. Excel's "CSV UTF-8" adds the UTF-8 one.
  let encoding = 'utf-8';
  let start = 0;
  if (buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) start = 3;
  else if (buffer[0] === 0xff && buffer[1] === 0xfe) { encoding = 'utf-16le'; start = 2; }
  else if (buffer[0] === 0xfe && buffer[1] === 0xff) { encoding = 'utf-16be'; start = 2; }

  let text;
  try {
    // fatal: true means "throw on bad bytes" instead of silently inserting garbage characters.
    text = new TextDecoder(encoding, { fatal: true }).decode(buffer.subarray(start));
  } catch {
    throw new Error('The file is not valid UTF-8 text. Save or export it as "CSV UTF-8" (in Excel: Save As, then CSV UTF-8).');
  }
  if (text.includes('\u0000')) throw new Error('This does not look like a CSV text file.');
  return text;
}

// ---------------------------------------------------------------------------------------
// 2. Text -> rows (RFC 4180: quoted fields, "" for a quote, newlines allowed inside quotes)
// ---------------------------------------------------------------------------------------

// Browsers use commas, but Excel in some regions saves with semicolons (or tabs). Look at the
// header line only, ignoring anything inside quotes, and pick the most common separator.
function detectDelimiter(text) {
  const counts = DELIMITERS.map(() => 0);
  let inQuotes = false;
  for (const ch of text) {
    if (ch === '"') inQuotes = !inQuotes;
    else if (!inQuotes && (ch === '\n' || ch === '\r')) break;
    else if (!inQuotes && DELIMITERS.includes(ch)) counts[DELIMITERS.indexOf(ch)]++;
  }
  const best = Math.max(...counts);
  return best === 0 ? ',' : DELIMITERS[counts.indexOf(best)];
}

function parseCsv(text, delimiter = ',') {
  const rows = [];
  let row = [];
  let field = '';
  let atFieldStart = true; // a quote only OPENS a quoted field at the very start of a field
  let inQuotes = false;

  const endField = () => { row.push(field); field = ''; atFieldStart = true; };
  const endRow = () => { endField(); rows.push(row); row = []; };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch !== '"') field += ch;
      else if (text[i + 1] === '"') { field += '"'; i++; } // "" inside quotes = one literal quote
      else inQuotes = false;
    } else if (ch === '"' && atFieldStart) {
      inQuotes = true;
      atFieldStart = false;
    } else if (ch === delimiter) {
      endField();
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++; // CRLF counts as one line break
      endRow();
    } else {
      field += ch;
      atFieldStart = false;
    }
  }

  // Row numbers are never taken from the file's content, so this message cannot leak a password.
  if (inQuotes) throw new Error(`A quoted value starting on row ${rows.length + 1} is never closed.`);
  if (!atFieldStart || row.length > 0) endRow(); // last line without a trailing newline
  return rows;
}

// ---------------------------------------------------------------------------------------
// 3. Rows -> vault entries
// ---------------------------------------------------------------------------------------

// Header names used by Chrome / Edge / Brave, Firefox, Bitwarden, 1Password, LastPass,
// KeePass, Dashlane and Apple Passwords. Matching ignores case, spaces and punctuation, so
// "Login Name", "login_name" and "loginname" are all the same. The ORDER matters: when a file
// has several matching columns, the first non-empty one wins.
const COLUMN_ALIASES = {
  label:    ['site', 'name', 'title', 'account', 'accountname', 'service'],
  url:      ['url', 'website', 'weburl', 'loginuri', 'loginurl', 'origin'],
  username: ['username', 'user', 'loginusername', 'loginname', 'login', 'userid', 'email', 'emailaddress'],
  password: ['password', 'loginpassword', 'pass'],
  notes:    ['notes', 'note', 'extra', 'comments', 'comment'],
  category: ['category', 'folder', 'grouping', 'type'],
  favorite: ['favorite', 'favourite', 'fav'],
  // Written by the export part (PART 2 below): one code per line inside the cell. Other apps do not have this column.
  backupCodes: ['backupcodes', 'backupcode', 'recoverycodes']
};

const normalizeHeader = (header) => header.toLowerCase().replace(/[^a-z0-9]/g, '');

function mapColumns(headerRow) {
  const normalized = headerRow.map(normalizeHeader);
  const used = new Set();
  const columns = {};

  for (const [field, names] of Object.entries(COLUMN_ALIASES)) {
    columns[field] = [];
    for (const name of names) {
      normalized.forEach((header, index) => {
        if (header === name) { columns[field].push(index); used.add(index); }
      });
    }
  }

  if (columns.password.length === 0 || (columns.label.length === 0 && columns.url.length === 0)) {
    // Deliberately does not repeat anything from the file: if the file has no header row,
    // the "header" would be a real entry, password included.
    throw new Error('Could not find the needed columns. The first row must be a header with a password column and a name, title, site or URL column (for example: name, url, username, password).');
  }

  const ignoredColumns = headerRow
    .filter((header, index) => !used.has(index) && header.trim() !== '')
    .map((header) => header.trim().slice(0, 30))
    .slice(0, 10);
  return { columns, ignoredColumns };
}

// First non-empty cell among the given columns. Passwords are never trimmed: a space can be
// part of a password.
function pick(row, indices, trim = true) {
  for (const index of indices) {
    const value = row[index] ?? '';
    const candidate = trim ? value.trim() : value;
    if (candidate !== '') return candidate;
  }
  return '';
}

// The vault only knows six categories. Use the first category-like column whose value is one of
// them (so Bitwarden's folder "work" beats its type "login"), otherwise fall back to "login".
function pickCategory(row, indices) {
  for (const index of indices) {
    const value = (row[index] ?? '').trim().toLowerCase();
    if (PasswordVault.CATEGORIES.has(value)) return value;
  }
  return 'login';
}

function hostFromUrl(value) {
  if (!value) return '';
  try {
    const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
    const host = new URL(hasScheme ? value : `https://${value}`).hostname.replace(/^www\./i, '');
    return host ? domainToUnicode(host) : value;
  } catch {
    return value;
  }
}

function rowToEntry(row, columns) {
  const label = pick(row, columns.label);
  const url = pick(row, columns.url);
  const host = hostFromUrl(url);

  // Line endings in notes are made uniform (Windows exports use CRLF). Passwords are never touched.
  // The vault has no URL field, so keep a URL that the site name does not already show.
  let notes = pick(row, columns.notes, false).replace(/\r\n?/g, '\n');
  // (hostFromUrl also drops "www.", so a site named "www.example.com" matches its own URL.)
  // Skipped when the notes already carry that exact line, so exporting and re-importing the same
  // entry does not stack up copies of it.
  const urlLine = `URL: ${url}`;
  if (label && url && host.toLowerCase() !== hostFromUrl(label).toLowerCase() && !notes.split('\n').includes(urlLine)) {
    notes += `${notes ? '\n' : ''}${urlLine}`;
  }

  return {
    site: label || host,
    username: pick(row, columns.username),
    password: pick(row, columns.password, false),
    notes,
    category: pickCategory(row, columns.category),
    favorite: TRUTHY.has(pick(row, columns.favorite).toLowerCase()),
    // Same parser as the "Backup codes" box in the app. Codes are split on line breaks, commas and
    // semicolons (not spaces), and repeats are dropped. The vault's own rules (at most 50, 128
    // characters each) are applied below by validateEntry.
    backupCodes: parseBackupCodes(pick(row, columns.backupCodes, false), { splitOnSpaces: false })
  };
}

// Bytes in, { entries, problems, ignoredColumns, rowCount } out. Problems are { row, reason }
// with the row number as a spreadsheet shows it (row 1 is the header). Reasons are fixed
// sentences and never contain values from the file.
function parseVaultCsv(buffer) {
  const text = decodeText(buffer);
  const rows = parseCsv(text, detectDelimiter(text));

  if (rows.length < 2) throw new Error('The file has no entries (it needs a header row followed by at least one row).');
  if (rows.length - 1 > MAX_ENTRIES) {
    throw new Error(`The file has more than ${MAX_ENTRIES} rows, which is more than the vault can hold.`);
  }

  const { columns, ignoredColumns } = mapColumns(rows[0]);
  const entries = [];
  const problems = [];

  for (let index = 1; index < rows.length; index++) {
    const row = rows[index];
    if (row.every((cell) => cell.trim() === '')) continue; // blank line

    const entry = rowToEntry(row, columns);
    try {
      if (entry.password === '') throw new Error('No password (secure notes and passkeys are skipped).');
      PasswordVault.validateEntry(entry); // the exact same rules as an entry typed in by hand
      entries.push(entry);
    } catch (error) {
      problems.push({ row: index + 1, reason: error.message });
    }
  }

  return { entries, problems, ignoredColumns, rowCount: rows.length - 1 };
}

// ---------------------------------------------------------------------------------------
// 4. Merging into the vault
// ---------------------------------------------------------------------------------------
//
// The vault allows ONE entry per site name, but real exports often hold several accounts for
// one site. Rather than dropping them, a clash gets the username added to its name:
// "github.com", then "github.com (bob)", then "github.com (bob) 2", and so on.
// An entry that is identical (same name, username AND password) to what is already there is
// skipped instead, so importing the same file twice adds nothing. Nothing is ever overwritten.

const siteKey = (site) => site.trim().toLowerCase();
const fit = (text, suffix) => text.slice(0, MAX_SITE_LENGTH - suffix.length) + suffix;

function* siteLabels(site, username) {
  yield site;
  const base = username ? fit(site, ` (${username.slice(0, MAX_TAG_LENGTH)})`) : site;
  if (username) yield base;
  for (let n = 2; ; n++) yield fit(base, ` ${n}`);
}

function planImport(existingEntries, candidates) {
  const occupied = new Map(existingEntries.map((entry) => [siteKey(entry.site), entry]));
  const additions = [];
  let duplicates = 0;
  let renamed = 0;

  for (const candidate of candidates) {
    for (const label of siteLabels(candidate.site, candidate.username)) {
      const holder = occupied.get(siteKey(label));
      if (!holder) {
        const entry = { ...candidate, site: label };
        occupied.set(siteKey(label), entry);
        additions.push(entry);
        if (label !== candidate.site) renamed++;
        break;
      }
      if (holder.username === candidate.username && holder.password === candidate.password) {
        duplicates++;
        break;
      }
    }
  }
  return { additions, duplicates, renamed };
}

// Read-only: what WOULD happen. Used for the confirmation dialog.
async function previewImport(vault, candidates) {
  const entries = await vault.loadEntries();
  const { additions, duplicates, renamed } = planImport(entries, candidates);
  return { toAdd: additions.length, duplicates, renamed };
}

// All-or-nothing: one read, one encrypted write (the vault writes to a temp file and renames
// it into place), so a failure part-way leaves the vault exactly as it was.
function importEntries(vault, candidates) {
  return vault.runWriteTransaction(async () => {
    const key = vault.requireKey();
    const { envelope, entries } = await vault.readEntriesForWrite(key);
    const { additions, duplicates, renamed } = planImport(entries, candidates);

    if (entries.length + additions.length > MAX_ENTRIES) {
      throw new Error(`Importing ${additions.length} entries would pass the vault limit of ${MAX_ENTRIES} (it holds ${entries.length} now).`);
    }
    if (additions.length === 0) return { added: 0, duplicates, renamed };

    const now = new Date().toISOString();
    const stored = additions.map((entry) => ({
      id: crypto.randomUUID(),
      site: entry.site,
      username: entry.username,
      password: entry.password,
      notes: entry.notes,
      category: entry.category,
      favorite: entry.favorite,
      backupCodes: entry.backupCodes.map(PasswordVault.createBackupCode),
      createdAt: now,
      updatedAt: now
    }));

    await vault.persistEntries([...entries, ...stored], key, envelope);
    return { added: stored.length, duplicates, renamed };
  });
}

// =======================================================================================
// PART 2: EXPORT
// =======================================================================================

// CSV export for the password vault.
//
// Pure logic, like the import part above: vault entries in, CSV text out. No Electron, no files.
//
// The columns follow the layout most browsers and password managers use for their own exports
// (name, url, username, password, note) plus three extras (category, favorite, backup_codes) so
// that a file exported here can be imported back into VLAUTR without losing anything that still
// matters. Backup codes that are already marked as used are left out: they no longer work anywhere. I have not tested
// other apps' importers, so check one with a throwaway entry before moving everything.
//
// Values are written exactly as stored. Some exporters add a leading ' to values that start with
// = + - @ to stop Excel treating them as formulas, but that would silently change real passwords
// and usernames (a generated password can easily start with + or @). The export dialog tells
// people to import the file into a password manager rather than open it in Excel.

const HEADER = ['name', 'url', 'username', 'password', 'note', 'category', 'favorite', 'backup_codes'];

// Quote a value when it contains a comma, a quote or a line break, or has leading or trailing
// spaces (which some readers trim). Inside quotes a literal quote is written as two quotes.
function csvField(value) {
  const text = String(value ?? '');
  return /[",\r\n]|^\s|\s$/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

// The vault has no URL field, so a URL comes from one of two places:
//   * the site name, when it is plainly a domain ("github.com" -> https://github.com), or
//   * a "URL: https://..." line in the notes, which is where the import part keeps the URL of a
//     browser export whose entries have a friendly name.
// Importers that insist on a URL column (Chrome, for one) then accept the row.
const DOMAIN = /^(?:[\p{L}\p{N}-]+\.)+[\p{L}\p{N}-]{2,}$/u;
const NOTE_URL = /^URL: (https?:\/\/\S+)$/m;
const urlFor = (entry) => (DOMAIN.test(entry.site) ? `https://${entry.site}` : entry.notes.match(NOTE_URL)?.[1] ?? '');

// One code per line, inside a single quoted cell. (A code that itself contains a comma or a
// semicolon would be split when imported again; real backup codes do not.)
const unusedBackupCodes = (entry) => (entry.backupCodes ?? []).filter((code) => !code.used).map((code) => code.code).join('\n');

function buildVaultCsv(entries) {
  const sorted = [...entries].sort((a, b) =>
    a.site.localeCompare(b.site, undefined, { sensitivity: 'base' }));

  const lines = [HEADER.join(',')];
  for (const entry of sorted) {
    lines.push([
      entry.site,
      urlFor(entry),
      entry.username,
      entry.password,
      entry.notes,
      entry.category,
      entry.favorite === true ? 'true' : 'false',
      unusedBackupCodes(entry)
    ].map(csvField).join(','));
  }
  return `${lines.join('\r\n')}\r\n`; // RFC 4180 line endings
}

// "vlautr-export-2026-11-04.csv" (local date)
function exportFileName(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `vlautr-export-${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}.csv`;
}

// =======================================================================================
// PART 3: ELECTRON SIDE (file pickers, confirmations, IPC handlers)
// =======================================================================================

// Electron side of CSV import and export. Electron objects (dialog, window) are passed in rather
// than required here, so the whole flow can be tested without starting Electron.
//
// Security design, for both directions:
//   * The page only says "import" or "export". It never supplies a file path and never sees the
//     CSV text; the main process opens the file pickers itself and talks to the user through
//     its own native dialogs, which page code cannot click or fake.
//   * What comes back to the page is counts, row numbers and a file NAME, never file content.
//   * Nothing is written until the person has confirmed. Import takes an encrypted backup first.

const MAX_PROBLEMS_SENT = 50;
const count = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// File system errors carry the full path ("ENOENT: no such file, open 'C:\\Users\\...'"). The page
// only ever sees one of these fixed sentences instead.
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

// ---------------------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------------------

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
    buffer.fill(0); // wipe the raw file bytes as soon as they have been parsed
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

    const backupName = await vault.createBackup('pre-import');
    const result = await importEntries(vault, parsed.entries);

    let csvDeleted = false;
    if (choice.response === IMPORT_AND_DELETE) {
      try {
        await fs.rm(filePath); // only reached after the import was written successfully
        csvDeleted = true;
      } catch {}
    }

    onActivity();
    return { success: true, ...result, backupName, csvDeleted, ...report };
  }, { cancelsRestoreToken: true }); // an import changes the vault, so any restore preview is stale
}

// ---------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------

const EXPORT_CONTINUE = 0;
const EXPORT_CANCEL = 1;

// Folders that sync to the cloud. Best effort: it catches the usual default folder names only.
const SYNCED_FOLDER = /[\\/](onedrive|dropbox|google ?drive|icloud ?drive|box sync)[^\\/]*[\\/]/i;

function registerExport({ registerVaultHandler, getVault, getParentWindow, dialog, getDefaultDirectory, onActivity }) {
  registerVaultHandler('vault:export-csv', async () => {
    const vault = getVault();
    if (!vault?.isUnlocked()) throw new Error('Unlock the vault first.');
    const parent = getParentWindow();

    const total = (await vault.loadEntries()).length;
    if (total === 0) throw new Error('Your vault has no entries to export.');

    // 1. Say plainly what is about to happen. This is the point where the person can back out.
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

    // 2. Where to save. The page cannot choose the path; only the person can.
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

    // 3. Only now are the passwords read, so nothing waits in memory behind an open dialog. If the
    // vault auto-locked while a dialog was open, this throws and nothing is written.
    const entries = await vault.loadEntries();
    const data = Buffer.from(buildVaultCsv(entries), 'utf8');
    try {
      // Owner-only where the OS supports it (it has no effect on Windows).
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

module.exports = {
  // import
  MAX_CSV_BYTES, parseCsv, parseVaultCsv, planImport, previewImport, importEntries,
  // export
  HEADER, buildVaultCsv, exportFileName,
  // Electron side
  registerCsvHandlers
};
