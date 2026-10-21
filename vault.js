const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');

const pbkdf2 = promisify(crypto.pbkdf2);
const FORMAT_VERSION = 2;
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
const MAX_MASTER_PASSWORD_LENGTH = 1024;
const CATEGORIES = new Set(['login', 'email', 'finance', 'identity', 'work', 'other']);

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
      return { exists: true, legacy: envelope.version === LEGACY_FORMAT_VERSION, corrupted: false };
    } catch {
      return { exists: true, legacy: false, corrupted: true };
    }
  }

  async createBackup() {
    let contents;
    try {
      contents = await fs.readFile(this.filePath);
    } catch (error) {
      if (error.code === 'ENOENT') throw new Error('There is no vault file to back up.');
      throw error;
    }

    const backupName = `vault-backup-${Date.now()}-${crypto.randomUUID()}.bak`;
    await fs.writeFile(path.join(path.dirname(this.filePath), backupName), contents, { flag: 'wx', mode: 0o600 });
    return backupName;
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

    const migrated = envelope.version === LEGACY_FORMAT_VERSION;
    if (migrated) {
      try {
        const migratedEntries = migrateEntries(entries);
        validateEntries(migratedEntries);
        await backupLegacyVault(this.filePath, contents);
        await this.persistEntries(migratedEntries, candidateKey, envelope);
      } catch (error) {
        candidateKey.fill(0);
        throw new Error(`Could not upgrade the vault: ${error.message}`);
      }
    }

    this.replaceKey(candidateKey);
    return { created: false, migrated };
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
        createdAt: now,
        updatedAt: now
      });

      await this.persistEntries(entries, key, envelope);
    });
  }

  async updateEntry(id, entry) {
    validateEntry(entry);
    validateEntryId(id);
    return this.runWriteTransaction(async () => {
      const key = this.requireKey();
      const { envelope, entries } = await this.readEntriesForWrite(key);
      const index = entries.findIndex((savedEntry) => savedEntry.id === id);

      if (index === -1) throw new Error('Entry not found.');
      ensureUniqueSite(entries, entry.site, id);

      const current = entries[index];
      entries[index] = {
        id,
        site: entry.site.trim(),
        username: entry.username,
        password: entry.password,
        notes: entry.notes,
        category: entry.category,
        favorite: entry.favorite,
        createdAt: current.createdAt,
        updatedAt: entry.password === current.password ? current.updatedAt : new Date().toISOString()
      };

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
    else validateEntries(entries);
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
      createdAt: entry.createdAt ?? now,
      updatedAt: entry.updatedAt ?? now
    };
  });
}

async function backupLegacyVault(filePath, contents) {
  const backupPath = `${filePath}.v1-${Date.now()}-${crypto.randomUUID()}.bak`;
  await fs.writeFile(backupPath, contents, { flag: 'wx', mode: 0o600 });
  return backupPath;
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

async function writeVaultFile(filePath, envelope) {
  const temporaryPath = `${filePath}.tmp`;
  await fs.mkdir(path.dirname(filePath), { recursive: true });

  try {
    const contents = JSON.stringify(envelope, null, 2);
    if (Buffer.byteLength(contents, 'utf8') > MAX_VAULT_BYTES) {
      throw new Error('Vault has reached its maximum file size.');
    }
    await fs.writeFile(temporaryPath, contents, { mode: 0o600 });
    await fs.rename(temporaryPath, filePath);
  } catch (error) {
    await fs.rm(temporaryPath, { force: true }).catch(() => {});
    throw error;
  }
}

function validateEnvelope(envelope) {
  if (!envelope || typeof envelope !== 'object' || Array.isArray(envelope)) {
    throw new Error('Invalid vault envelope.');
  }
  if (![LEGACY_FORMAT_VERSION, FORMAT_VERSION].includes(envelope.version) || envelope.kdf !== 'pbkdf2-sha256' || envelope.cipher !== 'aes-256-gcm') {
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
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error('Invalid encoded vault data.');
  }

  const decoded = Buffer.from(value, 'base64');
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
  const requiredFields = ['site', 'username', 'password', 'notes', 'category', 'favorite'];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || requiredFields.some((field) => !Object.hasOwn(entry, field))) {
    throw new Error('Entry must include site, username, password, notes, category, and favorite.');
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
}

function validateEntryId(id) {
  if (!isValidEntryId(id)) throw new Error('Invalid entry id.');
}

function isValidEntryId(id) {
  return typeof id === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id);
}

function validateStoredEntry(entry) {
  const expectedKeys = ['category', 'createdAt', 'favorite', 'id', 'notes', 'password', 'site', 'updatedAt', 'username'];
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).sort().join(',') !== expectedKeys.join(',')) {
    throw new Error('Invalid vault entry fields.');
  }
  validateEntry({
    site: entry.site,
    username: entry.username,
    password: entry.password,
    notes: entry.notes,
    category: entry.category,
    favorite: entry.favorite
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

function validateEntries(entries) {
  if (!Array.isArray(entries) || entries.length > MAX_ENTRIES) {
    throw new Error('Invalid vault entries.');
  }
  const ids = new Set();
  entries.forEach((entry) => {
    validateStoredEntry(entry);
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

module.exports = PasswordVault;
