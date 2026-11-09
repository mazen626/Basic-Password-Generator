'use strict';
const crypto = require('node:crypto');
const { domainToUnicode } = require('node:url');
const PasswordVault = require('./vault');
const { parseBackupCodes } = require('./backup-codes');

const { MAX_ENTRIES, MAX_SITE_LENGTH } = PasswordVault.LIMITS;
const MAX_CSV_BYTES = 5 * 1024 * 1024;
const MAX_TAG_LENGTH = 40;
const DELIMITERS = [',', ';', '\t'];
const TRUTHY = new Set(['1', 'true', 'yes', 'y', 'x']);

function decodeText(buffer) {
  if (buffer.length > MAX_CSV_BYTES) {
    throw new Error('That file is too large to be a password export (limit 5 MB).');
  }
  let encoding = 'utf-8';
  let start = 0;
  if (buffer[0] === 0xef && buffer[1] === 0xbb && buffer[2] === 0xbf) start = 3;
  else if (buffer[0] === 0xff && buffer[1] === 0xfe) { encoding = 'utf-16le'; start = 2; }
  else if (buffer[0] === 0xfe && buffer[1] === 0xff) { encoding = 'utf-16be'; start = 2; }

  let text;
  try {
    text = new TextDecoder(encoding, { fatal: true }).decode(buffer.subarray(start));
  } catch {
    throw new Error('The file is not valid UTF-8 text. Save or export it as "CSV UTF-8" (in Excel: Save As, then CSV UTF-8).');
  }
  if (text.includes('\u0000')) throw new Error('This does not look like a CSV text file.');
  return text;
}
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
  let atFieldStart = true;
  let inQuotes = false;

  const endField = () => { row.push(field); field = ''; atFieldStart = true; };
  const endRow = () => { endField(); rows.push(row); row = []; };

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch !== '"') field += ch;
      else if (text[i + 1] === '"') { field += '"'; i++; }
      else inQuotes = false;
    } else if (ch === '"' && atFieldStart) {
      inQuotes = true;
      atFieldStart = false;
    } else if (ch === delimiter) {
      endField();
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++;
      endRow();
    } else {
      field += ch;
      atFieldStart = false;
    }
  }
  if (inQuotes) throw new Error(`A quoted value starting on row ${rows.length + 1} is never closed.`);
  if (!atFieldStart || row.length > 0) endRow(); // last line without a trailing newline
  return rows;
}
const COLUMN_ALIASES = {
  label:    ['site', 'name', 'title', 'account', 'accountname', 'service'],
  url:      ['url', 'website', 'weburl', 'loginuri', 'loginurl', 'origin'],
  username: ['username', 'user', 'loginusername', 'loginname', 'login', 'userid', 'email', 'emailaddress'],
  password: ['password', 'loginpassword', 'pass'],
  notes:    ['notes', 'note', 'extra', 'comments', 'comment'],
  category: ['category', 'folder', 'grouping', 'type'],
  favorite: ['favorite', 'favourite', 'fav'],
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
    throw new Error('Could not find the needed columns. The first row must be a header with a password column and a name, title, site or URL column (for example: name, url, username, password).');
  }

  const ignoredColumns = headerRow
    .filter((header, index) => !used.has(index) && header.trim() !== '')
    .map((header) => header.trim().slice(0, 30))
    .slice(0, 10);
  return { columns, ignoredColumns };
}
function pick(row, indices, trim = true) {
  for (const index of indices) {
    const value = row[index] ?? '';
    const candidate = trim ? value.trim() : value;
    if (candidate !== '') return candidate;
  }
  return '';
}
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
  let notes = pick(row, columns.notes, false).replace(/\r\n?/g, '\n');
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
    backupCodes: parseBackupCodes(pick(row, columns.backupCodes, false), { splitOnSpaces: false })
  };
}
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
    if (row.every((cell) => cell.trim() === '')) continue;

    const entry = rowToEntry(row, columns);
    try {
      if (entry.password === '') throw new Error('No password (secure notes and passkeys are skipped).');
      PasswordVault.validateEntry(entry);
      entries.push(entry);
    } catch (error) {
      problems.push({ row: index + 1, reason: error.message });
    }
  }

  return { entries, problems, ignoredColumns, rowCount: rows.length - 1 };
}
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
async function previewImport(vault, candidates) {
  const entries = await vault.loadEntries();
  const { additions, duplicates, renamed } = planImport(entries, candidates);
  return { toAdd: additions.length, duplicates, renamed };
}
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

module.exports = { MAX_CSV_BYTES, parseCsv, parseVaultCsv, planImport, previewImport, importEntries };