const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');
const PasswordVault = require('../vault');
const { MASTER_PASSWORD: MASTER, createVault } = require('./helpers');
const { parseCsv, parseVaultCsv, planImport, previewImport, importEntries } = require('../csv-transfer');

const bytes = (text) => Buffer.from(text, 'utf8');

const makeVault = createVault; // temp directory + unlocked vault, from test/helpers.js

const candidate = (site, username, password) => ({
  site, username, password, notes: '', category: 'login', favorite: false, backupCodes: []
});

// ---------------------------------------------------------------------------------------
// The CSV parser
// ---------------------------------------------------------------------------------------

test('parseCsv handles quotes, escaped quotes, commas and newlines inside quotes', () => {
  const text = 'a,b,c\r\n"x,1","say ""hi""","line1\nline2"\r\n';
  assert.deepEqual(parseCsv(text), [
    ['a', 'b', 'c'],
    ['x,1', 'say "hi"', 'line1\nline2']
  ]);
});

test('parseCsv copes with missing final newline, trailing delimiter, empty quotes and bare CR', () => {
  assert.deepEqual(parseCsv('a,b\n1,2'), [['a', 'b'], ['1', '2']]);
  assert.deepEqual(parseCsv('a,b,\n1,2,'), [['a', 'b', ''], ['1', '2', '']]);
  assert.deepEqual(parseCsv('a,b\n"",x'), [['a', 'b'], ['', 'x']]);
  assert.deepEqual(parseCsv('a,b\r1,2\r'), [['a', 'b'], ['1', '2']]);
  assert.deepEqual(parseCsv('a,b\n"",""'), [['a', 'b'], ['', '']]);
  assert.deepEqual(parseCsv(''), []);
});

test('parseCsv keeps a quote that appears in the middle of an unquoted value', () => {
  assert.deepEqual(parseCsv('a,b\n5" nail,ok'), [['a', 'b'], ['5" nail', 'ok']]);
});

test('parseCsv rejects an unclosed quote without echoing the content', () => {
  assert.throws(
    () => parseCsv('a,b\n1,"SuperSecret123\n2,3'),
    (error) => /row 2/.test(error.message) && !error.message.includes('SuperSecret123')
  );
});

// ---------------------------------------------------------------------------------------
// Mapping real export formats to vault entries
// ---------------------------------------------------------------------------------------

test('Chrome export: maps columns and keeps tricky passwords exactly as they are', () => {
  const csv = [
    'name,url,username,password,note',
    'github.com,https://github.com/login,alice,"=p@ss,word""1",',
    'Bank,https://bank.example,bob,-starts with dash ,"line one',
    'line two"',
    'mail,https://mail.example,carol,@at+plus,'
  ].join('\r\n');
  const { entries, problems, ignoredColumns } = parseVaultCsv(bytes(csv));

  assert.deepEqual(problems, []);
  assert.deepEqual(ignoredColumns, []);
  assert.equal(entries.length, 3);
  assert.deepEqual(entries[0], {
    site: 'github.com', username: 'alice', password: '=p@ss,word"1',
    notes: '', category: 'login', favorite: false, backupCodes: []
  });
  // Leading = + - @ must NOT be stripped (that is only a concern when EXPORTING to Excel),
  // and the trailing space of a password must survive.
  assert.equal(entries[1].password, '-starts with dash ');
  assert.equal(entries[1].notes, 'line one\nline two\nURL: https://bank.example');
  assert.equal(entries[2].password, '@at+plus');
});

test('Bitwarden export: category, favorite, notes and the URL note', () => {
  const csv = [
    'folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp',
    'work,1,login,GitHub,my notes,,0,https://github.com,alice,pw-one,JBSWY3DPEHPK3PXP',
    ',0,note,Wi-Fi code,only a note,,0,,,,'
  ].join('\n');
  const { entries, problems, ignoredColumns } = parseVaultCsv(bytes(csv));

  assert.equal(entries.length, 1);
  assert.deepEqual(entries[0], {
    site: 'GitHub', username: 'alice', password: 'pw-one',
    notes: 'my notes\nURL: https://github.com', category: 'work', favorite: true, backupCodes: []
  });
  assert.deepEqual(problems, [{ row: 3, reason: 'No password (secure notes and passkeys are skipped).' }]);
  assert.deepEqual(ignoredColumns, ['fields', 'reprompt', 'login_totp']);
});

test('category: a known folder wins over the entry type, unknown folders fall back to the type', () => {
  const csv = [
    'folder,type,name,login_password',
    'Finance,login,A,pw',
    'Personal,identity,B,pw',
    'Personal,note,C,pw',
    ',login,D,pw'
  ].join('\n');
  const { entries } = parseVaultCsv(bytes(csv));
  assert.deepEqual(entries.map((e) => e.category), ['finance', 'identity', 'login', 'login']);
});

test('Firefox export: the site name comes from the URL host, www is dropped', () => {
  const csv = [
    'url,username,password,httpRealm,formActionOrigin,guid,timeCreated',
    'https://www.example.com/login,dave,pw,,https://www.example.com,{abc},1700000000000'
  ].join('\n');
  const { entries, ignoredColumns } = parseVaultCsv(bytes(csv));
  assert.equal(entries[0].site, 'example.com');
  assert.equal(entries[0].notes, '');
  assert.deepEqual(ignoredColumns, ['httpRealm', 'formActionOrigin', 'guid', 'timeCreated']);
});

test('semicolon and tab separated files are detected', () => {
  const semi = parseVaultCsv(bytes('name;url;username;password\nExample;https://e.example;eve;pw;1'));
  assert.equal(semi.entries[0].password, 'pw');
  const tabs = parseVaultCsv(bytes('title\tpassword\nExample\tp,w;x'));
  assert.equal(tabs.entries[0].password, 'p,w;x');
});

test('Arabic text and a UTF-8 byte order mark survive', () => {
  const csv = '﻿name,url,username,password,notes\nبنك,https://bank.example,مازن,كلمة-سر,ملاحظة';
  const { entries } = parseVaultCsv(bytes(csv));
  assert.equal(entries[0].site, 'بنك');
  assert.equal(entries[0].username, 'مازن');
  assert.equal(entries[0].password, 'كلمة-سر');
  assert.equal(entries[0].notes, 'ملاحظة\nURL: https://bank.example');
});

test('UTF-16 files with a byte order mark are decoded', () => {
  const text = 'name,password\nExample,pw';
  const le = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, 'utf16le')]);
  assert.equal(parseVaultCsv(le).entries[0].password, 'pw');
  const be = Buffer.from(le);
  be.swap16(); // turns the LE bytes (and the BOM) into BE
  assert.equal(parseVaultCsv(be).entries[0].password, 'pw');
});

test('rows that cannot be imported are reported by row number, never by content', () => {
  const csv = [
    'name,username,password,notes',
    'ok,a,fine-password,',
    '',
    `${'x'.repeat(201)},b,LeakyPass!9,`,
    '"multi',
    'line",c,AnotherSecret#1,',
    'empty,d,,'
  ].join('\n');
  const { entries, problems } = parseVaultCsv(bytes(csv));

  assert.equal(entries.length, 2); // 'ok' and the multi-line one
  // Rows are counted the way a spreadsheet counts them: the header is row 1, the blank line is
  // row 3, and the quoted value that spans two lines is a single row (5).
  assert.deepEqual(problems.map((p) => p.row), [4, 6]);
  const report = JSON.stringify(problems);
  for (const secret of ['LeakyPass!9', 'AnotherSecret#1', 'fine-password']) assert.ok(!report.includes(secret));
});

test('bad files fail with a clear message that never repeats file content', () => {
  const headerless = 'github.com,alice,SuperSecret123\nexample.com,bob,OtherSecret456';
  assert.throws(
    () => parseVaultCsv(bytes(headerless)),
    (error) => /needed columns/.test(error.message) && !/Secret/.test(error.message)
  );
  assert.throws(() => parseVaultCsv(bytes('name,password\n')), /no entries/);
  assert.throws(() => parseVaultCsv(bytes('')), /no entries/);
  assert.throws(() => parseVaultCsv(Buffer.from([0x50, 0x4b, 0x03, 0x04, 0xff, 0xfe, 0x00])), /UTF-8/);
  assert.throws(() => parseVaultCsv(bytes('name,password\nx,a\u0000b')), /does not look like/);
  assert.throws(() => parseVaultCsv(Buffer.alloc(5 * 1024 * 1024 + 1)), /too large/);
});

// ---------------------------------------------------------------------------------------
// Merging
// ---------------------------------------------------------------------------------------

test('planImport skips identical entries and renames clashing ones', () => {
  const existing = [{ site: 'Example', username: 'old', password: 'old-pw' }];
  const plan = planImport(existing, [
    candidate('example', 'old', 'old-pw'),   // identical to what is stored -> duplicate
    candidate('github.com', 'alice', 'p1'),
    candidate('github.com', 'bob', 'p2'),    // same site, other account -> renamed
    candidate('github.com', 'bob', 'p3'),    // same site AND username, new password -> 2nd rename
    candidate('github.com', 'alice', 'p1'),  // repeated inside the file -> duplicate
    candidate('Example', '', 'x')            // clashes, no username -> numbered
  ]);
  assert.deepEqual(plan.additions.map((e) => e.site), [
    'github.com', 'github.com (bob)', 'github.com (bob) 2', 'Example 2'
  ]);
  assert.equal(plan.duplicates, 2);
  assert.equal(plan.renamed, 3);
});

test('renamed sites never exceed the vault site-name limit', () => {
  const longSite = 's'.repeat(200);
  const plan = planImport([], [candidate(longSite, 'alice', 'p1'), candidate(longSite, 'bob', 'p2')]);
  assert.equal(plan.additions.length, 2);
  assert.ok(plan.additions.every((e) => e.site.length <= 200));
  assert.ok(plan.additions[1].site.endsWith(' (bob)'));
});

test('importing into a real vault: one write, valid entries, survives a reload, repeat adds nothing', async (t) => {
  const { vault, directory } = await makeVault(t);
  await vault.saveEntry({ site: 'Existing', username: 'me', password: 'mine', notes: '', category: 'work', favorite: true, backupCodes: [] });

  const csv = [
    'name,url,username,password,note',
    'github.com,https://github.com,alice,p1,',
    'github.com,https://github.com,bob,p2,',
    'Existing,https://existing.example,me,mine,',
    'مثال,https://example.sa,مازن,سر,'
  ].join('\n');
  const { entries: candidates } = parseVaultCsv(bytes(csv));

  assert.deepEqual(await previewImport(vault, candidates), { toAdd: 3, duplicates: 1, renamed: 1 });
  assert.deepEqual(await importEntries(vault, candidates), { added: 3, duplicates: 1, renamed: 1 });

  // A brand-new vault object has to be able to unlock and validate everything that was written.
  const reopened = new PasswordVault(path.join(directory, 'vault.json'));
  t.after(() => reopened.lock());
  await reopened.unlock(MASTER);
  const stored = await reopened.loadEntries();
  assert.deepEqual(stored.map((e) => e.site).sort(), ['Existing', 'github.com', 'github.com (bob)', 'مثال'].sort());
  assert.equal(stored.find((e) => e.site === 'Existing').favorite, true); // untouched

  assert.deepEqual(await importEntries(vault, candidates), { added: 0, duplicates: 4, renamed: 0 });
  assert.equal((await vault.loadEntries()).length, 4);
});

test('an import that would pass the entry limit changes nothing', async (t) => {
  const { vault, directory } = await makeVault(t);
  const vaultPath = path.join(directory, 'vault.json');
  const before = await fs.readFile(vaultPath, 'utf8');

  const tooMany = Array.from({ length: PasswordVault.LIMITS.MAX_ENTRIES + 1 }, (_, i) => candidate(`site-${i}`, 'u', 'p'));
  await assert.rejects(importEntries(vault, tooMany), /vault limit/);
  assert.equal(await fs.readFile(vaultPath, 'utf8'), before);
  assert.deepEqual(await fs.readdir(directory), ['vault.json']);
});

test('importing into a locked vault is refused', async (t) => {
  const { vault } = await makeVault(t);
  vault.lock();
  await assert.rejects(importEntries(vault, [candidate('a', 'b', 'c')]), /Unlock the vault first/);
});

test('a "www." site name matches its own URL, so no URL note is added', () => {
  const csv = 'name,url,username,password\nwww.example.com,https://www.example.com,a,pw\nexample.org,https://example.org/login,b,pw\nBank,https://bank.example,c,pw';
  const { entries } = parseVaultCsv(bytes(csv));
  assert.deepEqual(entries.map((e) => e.notes), ['', '', 'URL: https://bank.example']);
});

// ---------------------------------------------------------------------------------------
// Backup codes (an entry field since vault format 3)
// ---------------------------------------------------------------------------------------

test('backup codes: read from the backup_codes column, one per line, repeats dropped', () => {
  const csv = 'name,password,backup_codes\nA,pw,"1111-aaaa\r\n2222-bbbb\n1111-aaaa\n"\nB,pw,\nC,pw,"x y z; q-1"';
  const { entries, problems, ignoredColumns } = parseVaultCsv(bytes(csv));
  assert.deepEqual(problems, []);
  assert.deepEqual(ignoredColumns, []);
  assert.deepEqual(entries.map((e) => e.backupCodes), [['1111-aaaa', '2222-bbbb'], [], ['x y z', 'q-1']]);
});

test('backup codes: more than the vault allows is a skipped row, and the message holds no codes', () => {
  const many = Array.from({ length: 51 }, (_, i) => `CODE-SECRET-${i}`).join('\n');
  const { entries, problems } = parseVaultCsv(bytes(`name,password,backup_codes\nA,pw,"${many}"\nB,pw,ok-1`));
  assert.deepEqual(entries.map((e) => e.site), ['B']);
  assert.deepEqual(problems, [{ row: 2, reason: 'An entry can have up to 50 backup codes.' }]);
  assert.ok(!JSON.stringify(problems).includes('SECRET'));
});

test('backup codes are stored in the vault with fresh ids and start as unused', async (t) => {
  const { vault } = await makeVault(t);
  const { entries } = parseVaultCsv(bytes('name,password,backup_codes\nA,pw,"c1\nc2"'));
  await importEntries(vault, entries);

  const [stored] = await vault.loadEntries();
  assert.deepEqual(stored.backupCodes.map(({ code, used }) => ({ code, used })), [{ code: 'c1', used: false }, { code: 'c2', used: false }]);
  assert.equal(new Set(stored.backupCodes.map((c) => c.id)).size, 2);
});
