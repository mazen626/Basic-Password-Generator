const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');

const pbkdf2 = promisify(crypto.pbkdf2);
const FORMAT_VERSION = 3;
const PREVIOUS_FORMAT_VERSION = 2;
const LEGACY_FORMAT_VERSION = 1;
const PBKDF2_ITERATIONS = 600000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const MAX_VAULT_BYTES = 8 * 1024 * 1024;
const MAX_ENTRIES = 10000;
const MAX_SITE_LENGTH = 200;
const MAX_USERNAME_LENGTH = 255;
const MAX_PASSWORD_LENGTH = 4096;
const MAX_NOTES_LENGTH = 4000;
const MAX_BACKUP_CODES = 50;
const MAX_BACKUP_CODE_LENGTH = 128;
const MAX_MASTER_PASSWORD_LENGTH = 1024;
const CATEGORIES = new Set(['login', 'email', 'finance', 'identity', 'work', 'other']);
const MAX_BACKUP_ID_LENGTH = 128;
// File-name prefixes of the backups the app writes, by kind. Pre-upgrade backups are named after
// the vault file instead (see backupLegacyVault).
const BACKUP_PREFIXES = {
  backup: 'vault-backup',
  'pre-restore': 'vault-before-restore',
  'pre-password-change': 'vault-before-password-change',
  'pre-import': 'vault-before-import'
};
// The end of every backup name: a 13-digit millisecond timestamp, then a UUID in the lowercase
// hex that crypto.randomUUID() writes.
const BACKUP_SUFFIX = '-(\\d{13})-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\.bak';
// One message for a wrong password and for tampered or invalid backup contents, so a preview
// never tells the two apart.
const BACKUP_OPEN_ERROR = 'Incorrect password, or the backup is damaged.';
const PRE_RESTORE_ERROR = 'Could not save a copy of the current vault, so nothing was restored.';

class PasswordVault {
  constructor(filePath) {
    this.filePath = filePath;
    this.key = null;
    this.writeQueue = Promise.resolve();
  }

  isUnlocked() {
    return this.key !== null;
  }

  async hasVault() {
    try {
      await fs.access(this.filePath);
      return true;
    } catch (error) {
      if (error.code === 'ENOENT') return false;
      throw error;
    }
  }

  async getStatus() {
    let contents;
    try {
      contents = await fs.readFile(this.filePath, 'utf8');
    } catch (error) {
      if (error.code === 'ENOENT') return { exists: false, legacy: false, corrupted: false };
      throw error;
    }

    if (Buffer.byteLength(contents, 'utf8') > MAX_VAULT_BYTES) {
      return { exists: true, legacy: false, corrupted: true };
    }

    try {
      const envelope = validateEnvelope(JSON.parse(contents));
      return { exists: true, legacy: envelope.version !== FORMAT_VERSION, corrupted: false };
    } catch {
      return { exists: true, legacy: false, corrupted: true };
    }
  }

  // `kind` says why the backup is made (decision 5 of docs/PHASE-2A-DESIGN.md). The window's
  // "Create backup" passes nothing, so it always writes a plain `vault-backup-*` file.
  async createBackup(kind = 'backup') {
    let contents;
    try {
      contents = await fs.readFile(this.filePath);
    } catch (error) {
      if (error.code === 'ENOENT') throw new Error('There is no vault file to back up.');
      throw error;
    }

    return writeBackup(this.filePath, contents, kind);
  }

  // Checks a backup file name sent by the window and returns its kind and date. It must match one
  // of the backup name patterns exactly, so a path, `..` or a drive letter can never get through.
  validateBackupId(id) {
    const info = parseBackupId(id, path.basename(this.filePath));
    if (!info) throw new Error('Invalid backup id.');
    return info;
  }

  // Read-only inventory of the backups next to the vault file (docs/PHASE-2A-DESIGN.md, part B).
  // Each file is only parsed and checked against the envelope rules: no key is derived and nothing
  // is decrypted. Returns every backup found, valid ones first, each group newest first.
  async listBackups() {
    const directory = path.dirname(this.filePath);
    const vaultFileName = path.basename(this.filePath);
    let names;
    try {
      names = await fs.readdir(directory);
    } catch (error) {
      if (error.code === 'ENOENT') return [];
      throw new Error('Could not read the backup folder.');
    }

    const current = await readKeySettings(this.filePath);
    const items = [];
    for (const name of names) {
      const info = parseBackupId(name, vaultFileName);
      if (!info) continue;
      const item = await inspectBackup(path.join(directory, name), name, info, current);
      if (item) items.push(item);
    }

    return items.sort((a, b) => (
      (a.status === 'valid' ? 0 : 1) - (b.status === 'valid' ? 0 : 1) ||
      b.createdAt.localeCompare(a.createdAt) ||
      a.id.localeCompare(b.id)
    ));
  }

  // Restore preview (docs/PHASE-2A-DESIGN.md, part C). Opens one backup with its own password and
  // describes it, without touching the vault: nothing is written, and the vault's key and lock
  // state are never used or changed, so it works locked or unlocked. Version 1 and 2 backups are
  // also upgraded in memory (a dry run), so one that would fail its upgrade on unlock fails here.
  // Returns metadata only, plus the SHA-256 (hex) of the exact bytes that were checked.
  async previewBackup(id, password) {
    const info = this.validateBackupId(id);
    if (typeof password !== 'string' || password.length === 0 || password.length > MAX_MASTER_PASSWORD_LENGTH) {
      throw new Error('Enter the master password for this backup (1 to 1024 characters).');
    }

    const contents = await readBackupFile(path.join(path.dirname(this.filePath), id));
    const digest = crypto.createHash('sha256').update(contents).digest('hex');

    let envelope;
    try {
      envelope = validateEnvelope(JSON.parse(contents.toString('utf8')));
    } catch {
      throw new Error('Backup file is invalid or corrupted.');
    }
    if (info.legacyVersion !== null && envelope.version !== info.legacyVersion) {
      throw new Error('Backup file is invalid or corrupted.');
    }

    const key = await deriveKey(password, Buffer.from(envelope.salt, 'base64'), envelope.iterations);
    let entries;
    try {
      // decryptEntries checks the entries against the rules of the backup's own version.
      entries = decryptEntries(envelope, key);
      if (envelope.version !== FORMAT_VERSION) validateEntries(migrateEntries(entries));
    } catch {
      throw new Error(BACKUP_OPEN_ERROR);
    } finally {
      key.fill(0);
    }

    return { summary: summarizeBackup(entries, envelope.version), digest };
  }

  // Manual backup cleanup (docs/PHASE-2A-DESIGN.md, part E). Needs the vault unlocked. Runs as one
  // write transaction with its own fresh, uncapped scan, so the guards never come from the window.
  //
  // Guard rule, computed on that scan. These backups are never deleted, even if requested:
  //   1. the newest valid backup (reported "only valid backup" when it is the sole valid one, else
  //      "newest valid backup"), so a valid backup always remains if any exists;
  //   2. the newest valid backup whose password hint is `current`;
  //   3. the newest valid pre-restore backup, or, when no pre-restore backup is valid, the newest
  //      pre-restore file of any status.
  // Because these stay on disk whatever is requested, the set that remains always holds them.
  // Invalid, too-large and unreadable files are otherwise deletable. A requested id that is no
  // longer in the scan is reported as kept ("no longer exists"). Each file is deleted with a plain
  // unlink after an lstat shows a regular file; one failure doesn't stop the rest. Messages and
  // results never include a path.
  async deleteBackups(ids) {
    if (!Array.isArray(ids) || ids.length < 1 || ids.length > 1000 || new Set(ids).size !== ids.length) {
      throw new Error('Choose between 1 and 1000 different backups to delete.');
    }
    ids.forEach((id) => this.validateBackupId(id));
    const directory = path.dirname(this.filePath);

    return this.runWriteTransaction(async () => {
      this.requireKey();
      const scan = await this.listBackups();
      const protectedIds = computeProtectedBackups(scan);
      const present = new Set(scan.map((item) => item.id));
      const deleted = [];
      const kept = [];
      for (const id of ids) {
        if (!present.has(id)) {
          kept.push({ id, reason: 'no longer exists' });
        } else if (protectedIds.has(id)) {
          kept.push({ id, reason: protectedIds.get(id) });
        } else if (await unlinkRegularFile(path.join(directory, id))) {
          deleted.push(id);
        } else {
          kept.push({ id, reason: 'could not be deleted' });
        }
      }
      return { deleted, kept };
    });
  }

  // SHA-256 (hex) of the current vault file's bytes, read once, or 'absent' when there is none.
  // Streamed, so a vault of any size can be compared later without holding it in memory.
  async getVaultState() {
    let handle;
    try {
      handle = await fs.open(this.filePath, 'r');
    } catch (error) {
      if (error.code === 'ENOENT') return 'absent';
      throw new Error('Could not read the vault file.');
    }
    try {
      const hash = crypto.createHash('sha256');
      const buffer = Buffer.alloc(1024 * 1024);
      for (;;) {
        const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
        if (bytesRead === 0) break;
        hash.update(buffer.subarray(0, bytesRead));
      }
      return hash.digest('hex');
    } catch {
      throw new Error('Could not read the vault file.');
    } finally {
      await handle.close();
    }
  }

  // Transactional restore (docs/PHASE-2A-DESIGN.md, part D, steps 4 to 7). `expected` is what the
  // preview recorded: the backup's SHA-256 and the vault file's state (SHA-256 or 'absent'). Runs
  // as one write transaction, so no other write can happen in between. Order:
  //   1. read vault.json once and require its state to match;
  //   2. read the backup again, check its envelope and require its digest to match;
  //   3. refuse a backup identical to the current vault;
  //   4. save and verify the pre-restore copy (only when vault.json exists);
  //   5. write the backup bytes through the .tmp + flush + rename path;
  //   6. lock the vault.
  // Only the bytes read in steps 1 and 2 are used after the checks. Any failure before the rename
  // leaves vault.json and the key untouched. Errors never include a path.
  async restoreBackup(id, expected) {
    const info = this.validateBackupId(id);
    if (!expected || typeof expected.backupDigest !== 'string' || typeof expected.vaultState !== 'string') {
      throw new Error('Preview the backup again before restoring.');
    }

    return this.runWriteTransaction(async () => {
      const current = await readVaultForRestore(this.filePath);
      if ((current ? current.digest : 'absent') !== expected.vaultState) {
        throw new Error('The vault changed after the preview. Preview the backup again.');
      }

      const backup = await readBackupFile(path.join(path.dirname(this.filePath), id));
      try {
        const envelope = validateEnvelope(JSON.parse(backup.toString('utf8')));
        if (info.legacyVersion !== null && envelope.version !== info.legacyVersion) throw new Error('version');
      } catch {
        throw new Error('Backup file is invalid or corrupted.');
      }
      if (sha256Hex(backup) !== expected.backupDigest) {
        throw new Error('The backup changed after the preview. Preview the backup again.');
      }
      if (current && current.bytes && backup.equals(current.bytes)) {
        throw new Error('This backup is the same as the current vault.');
      }

      const preRestoreBackup = current ? await writePreRestoreCopy(this.filePath, current) : null;

      try {
        await writeVaultBytes(this.filePath, backup);
      } catch {
        throw new Error('Could not write the restored vault. The current vault was not changed.');
      }

      // The restored vault may use another master password, so the old key must not stay in use.
      this.lock();
      return { preRestoreBackup };
    });
  }

  async unlock(masterPassword, confirmation) {
    this.lock();
    validateMasterPassword(masterPassword);

    let contents;
    try {
      contents = await fs.readFile(this.filePath, 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      return this.initialize(masterPassword, confirmation);
    }

    if (Buffer.byteLength(contents, 'utf8') > MAX_VAULT_BYTES) {
      throw new Error('Vault file is too large.');
    }

    let envelope;
    try {
      envelope = validateEnvelope(JSON.parse(contents));
    } catch {
      throw new Error('Vault file is invalid or corrupted.');
    }

    const salt = Buffer.from(envelope.salt, 'base64');
    const candidateKey = await deriveKey(masterPassword, salt, envelope.iterations);
    let entries;

    try {
      entries = decryptEntries(envelope, candidateKey);
    } catch {
      candidateKey.fill(0);
      throw new Error('Incorrect master password or vault data is corrupted.');
    }

    const migrated = envelope.version !== FORMAT_VERSION;
    if (migrated) {
      try {
        const migratedEntries = migrateEntries(entries);
        validateEntries(migratedEntries);
        await backupLegacyVault(this.filePath, contents, envelope.version);
        await this.persistEntries(migratedEntries, candidateKey, envelope);
      } catch (error) {
        candidateKey.fill(0);
        throw new Error(`Could not upgrade the vault: ${error.message}`);
      }
    }

    this.replaceKey(candidateKey);
    return { created: false, migrated };
  }

  // Re-encrypts the vault under a new master password, with a fresh salt and the current
  // iteration count. The current password is checked first, and a byte-for-byte backup of the
  // vault is saved before the rewrite. Any failure before the rename leaves the old vault and the
  // old key in use. Backups made before the change still need the old password.
  async changeMasterPassword(currentPassword, newPassword, confirmation) {
    this.requireKey();
    if (typeof currentPassword !== 'string' || currentPassword.length === 0 || currentPassword.length > MAX_MASTER_PASSWORD_LENGTH) {
      throw new Error('Enter your current master password.');
    }
    validateMasterPassword(newPassword);
    validateMasterPasswordConfirmation(newPassword, confirmation);
    if (newPassword === currentPassword) {
      throw new Error('The new master password must be different from the current one.');
    }

    return this.runWriteTransaction(async () => {
      this.requireKey();
      const contents = await fs.readFile(this.filePath, 'utf8');
      if (Buffer.byteLength(contents, 'utf8') > MAX_VAULT_BYTES) throw new Error('Vault file is too large.');
      let envelope;
      try {
        envelope = validateEnvelope(JSON.parse(contents));
      } catch {
        throw new Error('Vault file is invalid or corrupted.');
      }
      if (envelope.version !== FORMAT_VERSION) throw new Error('Vault must be upgraded by unlocking again.');

      const currentKey = await deriveKey(currentPassword, Buffer.from(envelope.salt, 'base64'), envelope.iterations);
      let entries;
      try {
        entries = decryptEntries(envelope, currentKey);
      } catch {
        throw new Error('The current master password is incorrect.');
      } finally {
        currentKey.fill(0);
      }

      const backupName = await writeBackup(this.filePath, contents, 'pre-password-change');
      const salt = crypto.randomBytes(SALT_LENGTH);
      const newKey = await deriveKey(newPassword, salt, PBKDF2_ITERATIONS);
      try {
        validateEntries(entries);
        const newEnvelope = encryptEntries(entries, newKey, salt, PBKDF2_ITERATIONS);
        validateEntries(decryptEntries(newEnvelope, newKey));
        await writeVaultFile(this.filePath, newEnvelope);
      } catch (error) {
        newKey.fill(0);
        throw error;
      }

      this.replaceKey(newKey);
      return { backupName };
    });
  }

  async initialize(masterPassword, confirmation) {
    validateMasterPasswordConfirmation(masterPassword, confirmation);
    const salt = crypto.randomBytes(SALT_LENGTH);
    const key = await deriveKey(masterPassword, salt, PBKDF2_ITERATIONS);
    const envelope = encryptEntries([], key, salt);

    try {
      await writeVaultFile(this.filePath, envelope);
    } catch (error) {
      key.fill(0);
      throw error;
    }

    this.replaceKey(key);
    return { created: true, migrated: false };
  }

  lock() {
    if (this.key) this.key.fill(0);
    this.key = null;
  }

  async loadEntries() {
    const key = this.requireKey();
    const { entries } = await this.readEntriesForWrite(key);
    return entries;
  }

  // What the window gets at load: everything except passwords and backup code values.
  async loadEntrySummaries() {
    return (await this.loadEntries()).map(summarizeEntry);
  }

  async findEntry(id) {
    validateEntryId(id);
    const entry = (await this.loadEntries()).find((savedEntry) => savedEntry.id === id);
    if (!entry) throw new Error('Entry not found.');
    return entry;
  }

  async getEntrySite(id) {
    return (await this.findEntry(id)).site;
  }

  async getEntryPassword(id) {
    return (await this.findEntry(id)).password;
  }

  async getBackupCodes(id) {
    return (await this.findEntry(id)).backupCodes.map(({ id: codeId, code, used }) => ({ id: codeId, code, used }));
  }

  async saveEntry(entry) {
    validateEntry(entry);
    return this.runWriteTransaction(async () => {
      const key = this.requireKey();
      const { envelope, entries } = await this.readEntriesForWrite(key);
      ensureUniqueSite(entries, entry.site);

      if (entries.length >= MAX_ENTRIES) throw new Error('Vault entry limit reached.');

      const now = new Date().toISOString();
      entries.push({
        id: crypto.randomUUID(),
        site: entry.site.trim(),
        username: entry.username,
        password: entry.password,
        notes: entry.notes,
        category: entry.category,
        favorite: entry.favorite,
        backupCodes: entry.backupCodes.map(createBackupCode),
        createdAt: now,
        updatedAt: now
      });

      await this.persistEntries(entries, key, envelope);
    });
  }

  // Leaving out `password` or `backupCodes` keeps the saved value, so the window can edit
  // an entry without first loading its secrets.
  async updateEntry(id, entry) {
    validateEntryUpdate(entry);
    validateEntryId(id);
    return this.runWriteTransaction(async () => {
      const key = this.requireKey();
      const { envelope, entries } = await this.readEntriesForWrite(key);
      const index = entries.findIndex((savedEntry) => savedEntry.id === id);

      if (index === -1) throw new Error('Entry not found.');
      ensureUniqueSite(entries, entry.site, id);

      const current = entries[index];
      const password = Object.hasOwn(entry, 'password') ? entry.password : current.password;
      const codes = Object.hasOwn(entry, 'backupCodes') ? entry.backupCodes : current.backupCodes.map((saved) => saved.code);
      entries[index] = {
        id,
        site: entry.site.trim(),
        username: entry.username,
        password,
        notes: entry.notes,
        category: entry.category,
        favorite: entry.favorite,
        backupCodes: mergeBackupCodes(current.backupCodes, codes),
        createdAt: current.createdAt,
        updatedAt: password === current.password ? current.updatedAt : new Date().toISOString()
      };

      await this.persistEntries(entries, key, envelope);
    });
  }

  async setBackupCodeUsed(entryId, codeId, used) {
    validateEntryId(entryId);
    validateEntryId(codeId);
    if (typeof used !== 'boolean') throw new Error('Used must be true or false.');
    return this.runWriteTransaction(async () => {
      const key = this.requireKey();
      const { envelope, entries } = await this.readEntriesForWrite(key);
      const entry = entries.find((savedEntry) => savedEntry.id === entryId);
      if (!entry) throw new Error('Entry not found.');
      const code = entry.backupCodes.find((savedCode) => savedCode.id === codeId);
      if (!code) throw new Error('Backup code not found.');

      code.used = used;
      await this.persistEntries(entries, key, envelope);
    });
  }

  async deleteEntry(id) {
    validateEntryId(id);
    return this.runWriteTransaction(async () => {
      const key = this.requireKey();
      const { envelope, entries } = await this.readEntriesForWrite(key);
      const index = entries.findIndex((entry) => entry.id === id);

      if (index === -1) throw new Error('Entry not found.');
      entries.splice(index, 1);

      await this.persistEntries(entries, key, envelope);
    });
  }

  async readEntriesForWrite(key) {
    const envelope = await readVaultFile(this.filePath);
    if (envelope.version !== FORMAT_VERSION) throw new Error('Vault must be upgraded by unlocking again.');
    return { envelope, entries: decryptEntries(envelope, key) };
  }

  runWriteTransaction(operation) {
    const result = this.writeQueue.then(operation, operation);
    this.writeQueue = result.catch(() => {});
    return result;
  }

  async persistEntries(entries, key, envelope) {
    validateEntries(entries);
    await writeVaultFile(
      this.filePath,
      encryptEntries(entries, key, Buffer.from(envelope.salt, 'base64'), envelope.iterations)
    );
  }

  requireKey() {
    if (!this.key) throw new Error('Unlock the vault first.');
    return this.key;
  }

  replaceKey(key) {
    this.lock();
    this.key = key;
  }
}

async function deriveKey(masterPassword, salt, iterations) {
  const passwordBytes = Buffer.from(masterPassword, 'utf8');
  try {
    return await pbkdf2(passwordBytes, salt, iterations, 32, 'sha256');
  } finally {
    passwordBytes.fill(0);
  }
}

function encryptEntries(entries, key, salt, iterations = PBKDF2_ITERATIONS) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(entries), 'utf8'),
    cipher.final()
  ]);

  return {
    version: FORMAT_VERSION,
    kdf: 'pbkdf2-sha256',
    iterations,
    cipher: 'aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64')
  };
}

function decryptEntries(envelope, key) {
  const validated = validateEnvelope(envelope);
  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(validated.iv, 'base64')
  );
  decipher.setAuthTag(Buffer.from(validated.tag, 'base64'));
  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(validated.ciphertext, 'base64')),
    decipher.final()
  ]);

  try {
    const entries = JSON.parse(plaintext.toString('utf8'));
    if (validated.version === LEGACY_FORMAT_VERSION) validateLegacyEntries(entries);
    else validateEntries(entries, validated.version);
    return entries;
  } finally {
    plaintext.fill(0);
  }
}

function migrateEntries(entries) {
  const now = new Date().toISOString();
  const usedIds = new Set();
  return entries.map((entry) => {
    let id = isValidEntryId(entry.id) && !usedIds.has(entry.id) ? entry.id : crypto.randomUUID();
    while (usedIds.has(id)) id = crypto.randomUUID();
    usedIds.add(id);
    return {
      id,
      site: entry.site.trim(),
      username: entry.username ?? '',
      password: entry.password,
      notes: entry.notes ?? '',
      category: entry.category ?? 'login',
      favorite: entry.favorite ?? false,
      backupCodes: [],
      createdAt: entry.createdAt ?? now,
      updatedAt: entry.updatedAt ?? now
    };
  });
}

function summarizeEntry(entry) {
  return {
    id: entry.id,
    site: entry.site,
    username: entry.username,
    notes: entry.notes,
    category: entry.category,
    favorite: entry.favorite,
    createdAt: entry.createdAt,
    updatedAt: entry.updatedAt,
    hasPassword: entry.password.length > 0,
    backupCodes: {
      total: entry.backupCodes.length,
      unused: entry.backupCodes.filter((code) => !code.used).length
    }
  };
}

function createBackupCode(code) {
  return { id: crypto.randomUUID(), code, used: false };
}

function mergeBackupCodes(currentCodes, codes) {
  return codes.map((code) => currentCodes.find((saved) => saved.code === code) ?? createBackupCode(code));
}

async function backupLegacyVault(filePath, contents, version) {
  const backupPath = `${filePath}.v${version}-${Date.now()}-${crypto.randomUUID()}.bak`;
  await writeAndFlush(backupPath, contents, 'wx');
  return backupPath;
}

// Saves an exact copy of the vault file next to it, flushed to disk, and returns its name.
async function writeBackup(filePath, contents, kind = 'backup') {
  if (!Object.hasOwn(BACKUP_PREFIXES, kind)) throw new Error('Unknown backup kind.');
  const backupName = `${BACKUP_PREFIXES[kind]}-${Date.now()}-${crypto.randomUUID()}.bak`;
  await writeAndFlush(path.join(path.dirname(filePath), backupName), contents, 'wx');
  return backupName;
}

// Maps each protected backup id to its reason (see PasswordVault.deleteBackups). `scan` is the
// output of listBackups: valid first, then newest first.
function computeProtectedBackups(scan) {
  const protectedIds = new Map();
  const protect = (item, reason) => {
    if (item && !protectedIds.has(item.id)) protectedIds.set(item.id, reason);
  };
  const valid = scan.filter((item) => item.status === 'valid');
  protect(valid[0], valid.length === 1 ? 'only valid backup' : 'newest valid backup');
  protect(valid.find((item) => item.passwordHint === 'current'), 'newest backup that opens with the current password');
  protect(scan.find((item) => item.kind === 'pre-restore'), 'newest pre-restore backup');
  return protectedIds;
}

// Deletes one file only if it is a regular file (never a folder, symlink or junction). Returns
// true when it was deleted.
async function unlinkRegularFile(filePath) {
  try {
    const stats = await fs.lstat(filePath);
    if (!stats.isFile()) return false;
    await fs.unlink(filePath);
    return true;
  } catch {
    return false;
  }
}

function escapeRegExp(text) {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Returns { kind, createdAt (ms), legacyVersion } for a recognized backup file name, or null.
// Every pattern is a full match without the `i` flag, so each file has exactly one accepted
// spelling, and none allows a separator, `..` or a drive letter.
function parseBackupId(id, vaultFileName = 'vault.json') {
  if (typeof id !== 'string' || id.length === 0 || id.length > MAX_BACKUP_ID_LENGTH) return null;

  const legacy = new RegExp(`^${escapeRegExp(vaultFileName)}\\.v([12])${BACKUP_SUFFIX}$`).exec(id);
  if (legacy) return { kind: 'pre-upgrade', createdAt: Number(legacy[2]), legacyVersion: Number(legacy[1]) };

  for (const [kind, prefix] of Object.entries(BACKUP_PREFIXES)) {
    const match = new RegExp(`^${prefix}${BACKUP_SUFFIX}$`).exec(id);
    if (match) return { kind, createdAt: Number(match[1]), legacyVersion: null };
  }
  return null;
}

// Reads at most `limit` bytes, and returns null when the file holds more than that.
async function readFileBounded(filePath, limit) {
  const handle = await fs.open(filePath, 'r');
  try {
    const chunks = [];
    let total = 0;
    for (;;) {
      const buffer = Buffer.alloc(Math.min(1024 * 1024, limit + 1 - total));
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      chunks.push(buffer.subarray(0, bytesRead));
      total += bytesRead;
      if (total > limit) return null;
    }
    return Buffer.concat(chunks, total);
  } finally {
    await handle.close();
  }
}

// The salt and iteration count of the current vault file, or null if it is missing, too large,
// unreadable or invalid. Used only for comparison with backups and never returned.
async function readKeySettings(filePath) {
  try {
    const contents = await readFileBounded(filePath, MAX_VAULT_BYTES);
    if (!contents) return null;
    const envelope = validateEnvelope(JSON.parse(contents.toString('utf8')));
    return { salt: envelope.salt, iterations: envelope.iterations };
  } catch {
    return null;
  }
}

// Builds one inventory item, or returns null when the file is not listed (it disappeared, or it
// is not a regular file). Only the envelope is checked.
async function inspectBackup(backupPath, id, info, current) {
  const item = {
    id,
    kind: info.kind,
    createdAt: new Date(info.createdAt).toISOString(),
    size: 0,
    version: null,
    status: 'unreadable',
    passwordHint: 'unknown'
  };

  let stats;
  try {
    stats = await fs.lstat(backupPath);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    return item;
  }
  // Symlinks, junctions and folders are never listed.
  if (!stats.isFile()) return null;
  item.size = stats.size;
  if (stats.size > MAX_VAULT_BYTES) return { ...item, status: 'too-large' };

  let contents;
  try {
    contents = await readFileBounded(backupPath, MAX_VAULT_BYTES);
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    return item;
  }
  if (!contents) return { ...item, status: 'too-large' };

  let envelope;
  try {
    envelope = validateEnvelope(JSON.parse(contents.toString('utf8')));
  } catch {
    return { ...item, status: 'invalid' };
  }
  if (info.legacyVersion !== null && envelope.version !== info.legacyVersion) {
    return { ...item, status: 'invalid' };
  }

  let passwordHint = 'unknown';
  if (current) {
    passwordHint = envelope.salt === current.salt && envelope.iterations === current.iterations ? 'current' : 'other';
  }
  return { ...item, version: envelope.version, status: 'valid', passwordHint };
}

// Reads one backup for a preview, with the same rules as the inventory (inspectBackup): only a
// regular file (never a symlink, junction or folder), at most MAX_VAULT_BYTES. Errors never
// include the path.
async function readBackupFile(backupPath) {
  let stats;
  try {
    stats = await fs.lstat(backupPath);
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('Backup not found.');
    throw new Error('Could not read the backup.');
  }
  if (!stats.isFile()) throw new Error('Backup not found.');
  if (stats.size > MAX_VAULT_BYTES) throw new Error('Backup file is too large.');

  let contents;
  try {
    contents = await readFileBounded(backupPath, MAX_VAULT_BYTES);
  } catch (error) {
    if (error.code === 'ENOENT') throw new Error('Backup not found.');
    throw new Error('Could not read the backup.');
  }
  if (!contents) throw new Error('Backup file is too large.');
  return contents;
}

// Metadata only: no site names, usernames, passwords, notes, codes or key settings. Dates come
// from the entries as stored; a version 1 entry without a date is left out of the range rather
// than given the time of the preview.
function summarizeBackup(entries, version) {
  // The timestamps are already validated ISO strings; compare them as dates.
  const pick = (values, isBetter) => values
    .filter((value) => typeof value === 'string')
    .reduce((best, value) => (best === null || isBetter(Date.parse(value), Date.parse(best)) ? value : best), null);
  return {
    entryCount: entries.length,
    newestUpdatedAt: pick(entries.map((entry) => entry.updatedAt), (a, b) => a > b),
    oldestCreatedAt: pick(entries.map((entry) => entry.createdAt), (a, b) => a < b),
    version,
    willUpgrade: version !== FORMAT_VERSION
  };
}

async function readVaultFile(filePath) {
  const contents = await fs.readFile(filePath, 'utf8');
  if (Buffer.byteLength(contents, 'utf8') > MAX_VAULT_BYTES) {
    throw new Error('Vault file is too large.');
  }

  try {
    return validateEnvelope(JSON.parse(contents));
  } catch {
    throw new Error('Vault file is invalid or corrupted.');
  }
}

function sha256Hex(bytes) {
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

// Streams a file's SHA-256 (hex). Errors are passed on as they are.
async function hashFile(filePath) {
  const handle = await fs.open(filePath, 'r');
  try {
    const hash = crypto.createHash('sha256');
    const buffer = Buffer.alloc(1024 * 1024);
    for (;;) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
    return hash.digest('hex');
  } finally {
    await handle.close();
  }
}

// Reads vault.json once for a restore: null when there is none, otherwise { bytes, digest }. The
// digest always covers the whole file. A file over MAX_VAULT_BYTES is not kept in memory
// (`bytes` is null); its pre-restore copy is then made with copyFile and checked by this digest.
async function readVaultForRestore(filePath) {
  let handle;
  try {
    handle = await fs.open(filePath, 'r');
  } catch (error) {
    if (error.code === 'ENOENT') return null;
    throw new Error('Could not read the vault file.');
  }
  try {
    const hash = crypto.createHash('sha256');
    let chunks = [];
    let total = 0;
    for (;;) {
      const buffer = Buffer.alloc(1024 * 1024);
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      const chunk = buffer.subarray(0, bytesRead);
      hash.update(chunk);
      total += bytesRead;
      if (chunks && total <= MAX_VAULT_BYTES) chunks.push(chunk);
      else chunks = null;
    }
    return { bytes: chunks ? Buffer.concat(chunks, total) : null, digest: hash.digest('hex') };
  } catch {
    throw new Error('Could not read the vault file.');
  } finally {
    await handle.close();
  }
}

// Saves the vault as it was read for the restore to `vault-before-restore-<ms>-<uuid>.bak`,
// flushed, never overwriting a file, then reads the copy back and checks its SHA-256. On any
// failure the partial copy is removed (if this call created it) and the restore stops.
async function writePreRestoreCopy(filePath, current) {
  const name = `${BACKUP_PREFIXES['pre-restore']}-${Date.now()}-${crypto.randomUUID()}.bak`;
  const copyPath = path.join(path.dirname(filePath), name);
  try {
    if (current.bytes) {
      await writeAndFlush(copyPath, current.bytes, 'wx');
    } else {
      await fs.copyFile(filePath, copyPath, fs.constants.COPYFILE_EXCL);
      const handle = await fs.open(copyPath, 'r+');
      try {
        await handle.sync();
      } finally {
        await handle.close();
      }
    }
    if (await hashFile(copyPath) !== current.digest) throw new Error('digest mismatch');
  } catch (error) {
    // EEXIST means another file already had this name: it is not ours to remove.
    if (error.code !== 'EEXIST') await fs.rm(copyPath, { force: true }).catch(() => {});
    throw new Error(PRE_RESTORE_ERROR);
  }
  return name;
}

async function writeVaultFile(filePath, envelope) {
  return writeVaultBytes(filePath, JSON.stringify(envelope, null, 2));
}

// Replaces the vault file with `contents` (a string or bytes): written to vault.json.tmp, flushed,
// then renamed over vault.json. On failure the .tmp is removed and vault.json is unchanged.
async function writeVaultBytes(filePath, contents) {
  const temporaryPath = `${filePath}.tmp`;
  await fs.mkdir(path.dirname(filePath), { recursive: true });

  try {
    if (Buffer.byteLength(contents, 'utf8') > MAX_VAULT_BYTES) {
      throw new Error('Vault has reached its maximum file size.');
    }
    await writeAndFlush(temporaryPath, contents);
    await fs.rename(temporaryPath, filePath);
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  }
}

// Writes the file and flushes it to disk (FlushFileBuffers on Windows) before returning, so the
// new vault is fully on disk before it replaces the old one. Windows cannot flush a folder, so a
// power cut right after the rename can still lose the rename itself; the old vault then remains.
async function writeAndFlush(filePath, contents, flag = 'w') {
  const handle = await fs.open(filePath, flag, 0o600);
  try {
    await handle.writeFile(contents);
    await handle.sync();
  } finally {
    await handle.close();
  }
}

function validateEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new Error('Invalid vault envelope.');
  }
  if (![LEGACY_FORMAT_VERSION, PREVIOUS_FORMAT_VERSION, FORMAT_VERSION].includes(envelope.version) || envelope.kdf !== 'pbkdf2-sha256' || envelope.cipher !== 'aes-256-gcm') {
    throw new Error('Unsupported vault format.');
  }
  if (!Number.isInteger(envelope.iterations) || envelope.iterations < 100000 || envelope.iterations > 2000000) {
    throw new Error('Invalid key derivation settings.');
  }

  decodeBase64(envelope.salt, SALT_LENGTH, SALT_LENGTH);
  decodeBase64(envelope.iv, IV_LENGTH, IV_LENGTH);
  decodeBase64(envelope.tag, TAG_LENGTH, TAG_LENGTH);
  decodeBase64(envelope.ciphertext, 0, MAX_VAULT_BYTES);
  return envelope;
}

function decodeBase64(value, minimumLength, maximumLength) {
  if (typeof value !== 'string') throw new Error('Invalid encoded vault data.');

  // Buffer.from ignores characters that aren't base64, so only accept input that
  // re-encodes to exactly the same text. Unlike a regular expression, this has no
  // stack limit on large vaults.
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) throw new Error('Invalid encoded vault data.');
  if (decoded.length < minimumLength || decoded.length > maximumLength) {
    throw new Error('Invalid encoded vault data length.');
  }
  return decoded;
}

function validateMasterPassword(masterPassword) {
  if (typeof masterPassword !== 'string' || masterPassword.length < 8 || masterPassword.length > MAX_MASTER_PASSWORD_LENGTH) {
    throw new Error('Master password must be between 8 and 1024 characters.');
  }
}

function validateMasterPasswordConfirmation(masterPassword, confirmation) {
  if (typeof confirmation !== 'string' || confirmation !== masterPassword) {
    throw new Error('Master password confirmation does not match.');
  }
}

function validateEntry(entry) {
  const requiredFields = ['site', 'username', 'password', 'notes', 'category', 'favorite', 'backupCodes'];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || requiredFields.some((field) => !Object.hasOwn(entry, field))) {
    throw new Error('Entry must include site, username, password, notes, category, favorite, and backup codes.');
  }
  if (typeof entry.site !== 'string' || entry.site.trim().length === 0 || entry.site.length > MAX_SITE_LENGTH) {
    throw new Error('Site must contain 1 to 200 characters.');
  }
  if (typeof entry.username !== 'string' || entry.username.length > MAX_USERNAME_LENGTH) {
    throw new Error('Username must be 255 characters or fewer.');
  }
  if (typeof entry.password !== 'string' || entry.password.length === 0 || entry.password.length > MAX_PASSWORD_LENGTH) {
    throw new Error('Password must contain 1 to 4096 characters.');
  }
  if (typeof entry.notes !== 'string' || entry.notes.length > MAX_NOTES_LENGTH) {
    throw new Error('Notes must be 4000 characters or fewer.');
  }
  if (typeof entry.category !== 'string' || !CATEGORIES.has(entry.category)) {
    throw new Error('Choose a valid category.');
  }
  if (typeof entry.favorite !== 'boolean') {
    throw new Error('Favorite must be true or false.');
  }
  validateBackupCodes(entry.backupCodes);
}

function validateEntryUpdate(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    throw new Error('Entry must include site, username, password, notes, category, favorite, and backup codes.');
  }
  // Check the fields that were sent; an omitted password or code list is filled in from the saved entry.
  validateEntry({
    ...entry,
    password: Object.hasOwn(entry, 'password') ? entry.password : 'unchanged',
    backupCodes: Object.hasOwn(entry, 'backupCodes') ? entry.backupCodes : []
  });
}

function validateBackupCodes(codes) {
  if (!Array.isArray(codes) || codes.length > MAX_BACKUP_CODES) {
    throw new Error('An entry can have up to 50 backup codes.');
  }
  codes.forEach((code) => {
    if (typeof code !== 'string' || code.length === 0 || code.length > MAX_BACKUP_CODE_LENGTH || code !== code.trim() || /[\x00-\x1f\x7f]/.test(code)) {
      throw new Error('Each backup code must contain 1 to 128 characters.');
    }
  });
  if (new Set(codes).size !== codes.length) throw new Error('Backup codes must be unique.');
}

function validateStoredBackupCodes(codes) {
  if (!Array.isArray(codes)) throw new Error('Invalid backup codes.');
  const ids = new Set();
  codes.forEach((code) => {
    if (!code || typeof code !== 'object' || Array.isArray(code) || Object.keys(code).sort().join(',') !== 'code,id,used') {
      throw new Error('Invalid backup code fields.');
    }
    validateEntryId(code.id);
    if (typeof code.used !== 'boolean') throw new Error('Invalid backup code state.');
    if (ids.has(code.id)) throw new Error('Duplicate backup code id.');
    ids.add(code.id);
  });
}

function validateEntryId(id) {
  if (!isValidEntryId(id)) throw new Error('Invalid entry id.');
}

function isValidEntryId(id) {
  return typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
}

function validateStoredEntry(entry, formatVersion) {
  const expectedKeys = ['category', 'createdAt', 'favorite', 'id', 'notes', 'password', 'site', 'updatedAt', 'username'];
  if (formatVersion === FORMAT_VERSION) expectedKeys.unshift('backupCodes');
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).sort().join(',') !== expectedKeys.join(',')) {
    throw new Error('Invalid vault entry fields.');
  }
  const storedCodes = formatVersion === FORMAT_VERSION ? entry.backupCodes : [];
  validateStoredBackupCodes(storedCodes);
  validateEntry({
    site: entry.site,
    username: entry.username,
    password: entry.password,
    notes: entry.notes,
    category: entry.category,
    favorite: entry.favorite,
    backupCodes: storedCodes.map((storedCode) => storedCode.code)
  });
  validateEntryId(entry.id);
  validateTimestamp(entry.createdAt);
  validateTimestamp(entry.updatedAt);
}

function validateLegacyEntries(entries) {
  if (!Array.isArray(entries) || entries.length > MAX_ENTRIES) {
    throw new Error('Invalid legacy vault entries.');
  }

  entries.forEach((entry) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new Error('Invalid legacy vault entry.');
    }
    const allowedKeys = new Set(['id', 'site', 'username', 'password', 'notes', 'category', 'favorite', 'createdAt', 'updatedAt']);
    if (Object.keys(entry).some((key) => !allowedKeys.has(key)) || !Object.hasOwn(entry, 'site') || !Object.hasOwn(entry, 'password')) {
      throw new Error('Invalid legacy vault entry fields.');
    }
    if (typeof entry.site !== 'string' || entry.site.trim().length === 0 || entry.site.length > MAX_SITE_LENGTH) {
      throw new Error('Invalid legacy site.');
    }
    if (typeof entry.password !== 'string' || entry.password.length === 0 || entry.password.length > MAX_PASSWORD_LENGTH) {
      throw new Error('Invalid legacy password.');
    }
    if (entry.username !== undefined && (typeof entry.username !== 'string' || entry.username.length > MAX_USERNAME_LENGTH)) {
      throw new Error('Invalid legacy username.');
    }
    if (entry.notes !== undefined && (typeof entry.notes !== 'string' || entry.notes.length > MAX_NOTES_LENGTH)) {
      throw new Error('Invalid legacy notes.');
    }
    if (entry.category !== undefined && (typeof entry.category !== 'string' || !CATEGORIES.has(entry.category))) {
      throw new Error('Invalid legacy category.');
    }
    if (entry.favorite !== undefined && typeof entry.favorite !== 'boolean') {
      throw new Error('Invalid legacy favorite flag.');
    }
    if (entry.createdAt !== undefined) validateTimestamp(entry.createdAt);
    if (entry.updatedAt !== undefined) validateTimestamp(entry.updatedAt);
  });
}

function validateTimestamp(value) {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value)) || new Date(value).toISOString() !== value) {
    throw new Error('Invalid entry timestamp.');
  }
}

function validateEntries(entries, formatVersion = FORMAT_VERSION) {
  if (!Array.isArray(entries) || entries.length > MAX_ENTRIES) {
    throw new Error('Invalid vault entries.');
  }
  const ids = new Set();
  entries.forEach((entry) => {
    validateStoredEntry(entry, formatVersion);
    if (ids.has(entry.id)) throw new Error('Duplicate entry id.');
    ids.add(entry.id);
  });
}

function ensureUniqueSite(entries, site, ignoredId) {
  const normalizedSite = site.trim().toLowerCase();
  if (entries.some((entry) => entry.id !== ignoredId && entry.site.trim().toLowerCase() === normalizedSite)) {
    throw new Error('An entry for this site already exists.');
  }
}

// Shared with csv-transfer.js so imported rows are checked, and stored, by exactly the same rules
// as entries typed in by hand.
PasswordVault.validateEntry = validateEntry;
PasswordVault.createBackupCode = createBackupCode;
PasswordVault.CATEGORIES = CATEGORIES;
PasswordVault.LIMITS = { MAX_ENTRIES, MAX_SITE_LENGTH };
// Backup id check, shared with the later preview, restore and delete steps.
PasswordVault.parseBackupId = parseBackupId;

module.exports = PasswordVault;
