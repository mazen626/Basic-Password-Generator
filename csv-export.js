'use strict';

const HEADER = ['name', 'url', 'username', 'password', 'note', 'category', 'favorite', 'backup_codes'];
function csvField(value) {
  const text = String(value ?? '');
  return /[",\r\n]|^\s|\s$/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}
const DOMAIN = /^(?:[\p{L}\p{N}-]+\.)+[\p{L}\p{N}-]{2,}$/u;
const NOTE_URL = /^URL: (https?:\/\/\S+)$/m;
const urlFor = (entry) => (DOMAIN.test(entry.site) ? `https://${entry.site}` : entry.notes.match(NOTE_URL)?.[1] ?? '');
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
  return `${lines.join('\r\n')}\r\n`;
}

// "vlautr-export-2026-11-04.csv" (local date)
function exportFileName(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `vlautr-export-${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}.csv`;
}

module.exports = { HEADER, buildVaultCsv, exportFileName };