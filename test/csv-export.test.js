const assert = require('node:assert/strict');
const test = require('node:test');
const { HEADER, buildVaultCsv, exportFileName } = require('../csv-export');
const { parseCsv, parseVaultCsv } = require('../csv-import');

const entry = (site, username, password, extra = {}) => ({
  id: 'x', site, username, password, notes: '', category: 'login', favorite: false, backupCodes: [],
  createdAt: 't', updatedAt: 't', ...extra
});

test('export: header, CRLF line endings, sorted by site, favorite as true/false', () => {
  const csv = buildVaultCsv([
    entry('zeta', 'z', 'pz'),
    entry('Alpha', 'a', 'pa', { favorite: true, category: 'work', notes: 'hi' })
  ]);
  assert.equal(csv, [
    'name,url,username,password,note,category,favorite,backup_codes',
    'Alpha,,a,pa,hi,work,true,',
    'zeta,,z,pz,,login,false,',
    ''
  ].join('\r\n'));
  assert.deepEqual(csv.split('\r\n')[0].split(','), HEADER);
});

test('export: quotes only where needed and keeps values exactly as stored', () => {
  const csv = buildVaultCsv([entry('a', 'u', '=SUM(1,2)"x"', { notes: 'line1\nline2' })]);
  assert.deepEqual(parseCsv(csv)[1], ['a', '', 'u', '=SUM(1,2)"x"', 'line1\nline2', 'login', 'false', '']);
  // Leading = + - @ are NOT altered, because that would change real passwords.
  const risky = buildVaultCsv([entry('s', '+15551234567', '@pw'), entry('t', '-u', '+pw')]);
  assert.ok(risky.includes('s,,+15551234567,@pw,'));
  assert.ok(risky.includes('t,,-u,+pw,'));
  // Spaces at the ends of a value survive because the value is quoted.
  assert.ok(buildVaultCsv([entry('s', 'u', ' pw ')]).includes('," pw ",'));
});

test('export: a domain-like site name gets an https URL, other names do not', () => {
  const csv = buildVaultCsv([
    entry('github.com', 'a', 'p'), entry('My Bank', 'b', 'p'), entry('example.com/login', 'c', 'p'), entry('مثال.com', 'd', 'p')
  ]);
  const rows = Object.fromEntries(parseCsv(csv).slice(1).map((r) => [r[0], r[1]]));
  assert.deepEqual(rows, {
    'github.com': 'https://github.com',
    'My Bank': '',
    'example.com/login': '',
    'مثال.com': 'https://مثال.com'
  });
});

test('export: file names carry the local date', () => {
  assert.equal(exportFileName(new Date(2026, 10, 4)), 'vlautr-export-2026-11-04.csv');
  assert.equal(exportFileName(new Date(2027, 0, 9)), 'vlautr-export-2027-01-09.csv');
});

test('round trip: export then import gives back the same entries, with nothing ignored or skipped', () => {
  const original = [
    entry('github.com', 'alice', 'p@ss,word"1', { favorite: true, category: 'work', notes: 'first line\nsecond line' }),
    entry('GitHub', 'bob', '=1+1'),
    entry('www.example.com', '+15551234567', '@leading-at'),
    entry('My Bank', '', ' padded ', { category: 'finance', notes: 'He said "hi", twice' }),
    entry('مثال.com', 'مازن', 'كلمة-سر', { category: 'identity', notes: 'ملاحظة' }),
    entry('long-notes', 'u', 'two\nlines'),
    entry('with-codes', 'u', 'pw', { backupCodes: [{ id: '1', code: 'AAAA-1111', used: false }, { id: '2', code: 'BBBB 2222', used: true }, { id: '3', code: 'CCCC-3333', used: false }] })
  ];
  const { entries, problems, ignoredColumns } = parseVaultCsv(Buffer.from(buildVaultCsv(original), 'utf8'));

  assert.deepEqual(problems, []);
  assert.deepEqual(ignoredColumns, []);
  const key = (e) => e.site;
  // Used backup codes are deliberately not exported (they no longer work), so only unused ones come back.
  const want = original.map(({ site, username, password, notes, category, favorite, backupCodes }) => ({
    site, username, password, notes, category, favorite, backupCodes: backupCodes.filter((c) => !c.used).map((c) => c.code)
  }));
  assert.deepEqual([...entries].sort((a, b) => key(a).localeCompare(key(b))), want.sort((a, b) => key(a).localeCompare(key(b))));
});

test('export: a "URL:" line in the notes becomes the url column, and re-importing does not duplicate it', () => {
  const original = [entry('GitHub', 'alice', 'pw', { notes: 'work account\nURL: https://github.com/login' }), entry('Plain', 'bob', 'pw2', { notes: 'URL: not-a-url' })];
  const csv = buildVaultCsv(original);
  const rows = Object.fromEntries(parseCsv(csv).slice(1).map((r) => [r[0], r[1]]));
  assert.deepEqual(rows, { GitHub: 'https://github.com/login', Plain: '' });

  const { entries } = parseVaultCsv(Buffer.from(csv, 'utf8'));
  assert.deepEqual(entries.map((e) => e.notes).sort(), ['URL: not-a-url', 'work account\nURL: https://github.com/login']);
});

test('export: only unused backup codes are written, one per line in a single cell', () => {
  const csv = buildVaultCsv([entry('a', 'u', 'p', { backupCodes: [
    { id: '1', code: 'AAAA-1111', used: false }, { id: '2', code: 'USED-0000', used: true }, { id: '3', code: 'CCCC 3333', used: false }
  ] })]);
  assert.equal(parseCsv(csv)[1][7], 'AAAA-1111\nCCCC 3333');
  assert.ok(!csv.includes('USED-0000'));
});
