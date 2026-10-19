const crypto = require('node:crypto');
const fs = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');

const pbkdf2 = promisify(crypto.pbkdf2);
const FORMAT_VERSION = 1;
const PBKDF2_ITERATIONS = 600000;
const SALT_LENGTH = 16;
const IV_LENGTH = 12;
const TAG_LENGTH = 16;
const MAX_VAULT_BYTES = 8 * 1024 * 1024;
const MAX_ENTRIES = 10000;
const MAX_SITE_LENGTH = 200;
const MAX_PASSWORD_LENGTH = 4096;
const MAX_MASTER_PASSWORD_LENGTH = 1024;

class PasswordVault {
  constructor(filePath) {
    this.filePath = filePath;
    this.key = null;
  }

  async unlock(masterPassword) {
    this.lock();
    validateMasterPassword(masterPassword);

    let contents;
    try {
      contents = await fs.readFile(this.filePath, 'utf8');
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      return this.initialize(masterPassword);
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

    try {
      decryptEntries(envelope, candidateKey);
      this.replaceKey(candidateKey);
      return { created: false };
    } catch {
      candidateKey.fill(0);
      throw new Error('Incorrect master password or vault data is corrupted.');
    }
  }

  async initialize(masterPassword) {
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
    return { created: true };
  }

  lock() {
    if (this.key) this.key.fill(0);
    this.key = null;
  }

  async loadEntries() {
    const key = this.requireKey();
    const envelope = await readVaultFile(this.filePath);
    return decryptEntries(envelope, key);
  }

  async saveEntry(entry) {
    validateEntry(entry);
    const key = this.requireKey();
    const entries = await this.loadEntries();

    if (entries.length >= MAX_ENTRIES) {
      throw new Error('Vault entry limit reached.');
    }

    entries.push({ site: entry.site, password: entry.password });
    const envelope = await readVaultFile(this.filePath);
    await writeVaultFile(this.filePath, encryptEntries(entries, key, Buffer.from(envelope.salt, 'base64'), envelope.iterations));
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
    validateEntries(entries);
    return entries;
  } finally {
    plaintext.fill(0);
  }
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
  if (envelope.version !== FORMAT_VERSION || envelope.kdf !== 'pbkdf2-sha256' || envelope.cipher !== 'aes-256-gcm') {
    throw new Error('Unsupported vault format.');
  }
  if (!Number.isInteger(envelope.iterations) || envelope.iterations < 100000 || envelope.iterations > 2000000) {
    throw new Error('Invalid key derivation settings.');
  }

  const salt = decodeBase64(envelope.salt, SALT_LENGTH, SALT_LENGTH);
  const iv = decodeBase64(envelope.iv, IV_LENGTH, IV_LENGTH);
  const tag = decodeBase64(envelope.tag, TAG_LENGTH, TAG_LENGTH);
  decodeBase64(envelope.ciphertext, 0, MAX_VAULT_BYTES);

  if (!salt || !iv || !tag) throw new Error('Invalid vault encryption data.');
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

function validateEntry(entry) {
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || Object.keys(entry).length !== 2 || !Object.hasOwn(entry, 'site') || !Object.hasOwn(entry, 'password')) {
    throw new Error('Entry must contain only site and password.');
  }
  if (typeof entry.site !== 'string' || entry.site.trim().length === 0 || entry.site.length > MAX_SITE_LENGTH) {
    throw new Error('Site must contain 1 to 200 characters.');
  }
  if (typeof entry.password !== 'string' || entry.password.length === 0 || entry.password.length > MAX_PASSWORD_LENGTH) {
    throw new Error('Password must contain 1 to 4096 characters.');
  }
}

function validateEntries(entries) {
  if (!Array.isArray(entries) || entries.length > MAX_ENTRIES) {
    throw new Error('Invalid vault entries.');
  }
  entries.forEach(validateEntry);
}

module.exports = PasswordVault;
