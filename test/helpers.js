const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const PasswordVault = require('../vault');

const MASTER_PASSWORD = 'correct horse battery';

async function createTempDirectory(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'password-vault-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

async function createVault(t, { unlocked = true } = {}) {
  const directory = await createTempDirectory(t);
  const vaultPath = path.join(directory, 'vault.json');
  const vault = new PasswordVault(vaultPath);
  t.after(() => vault.lock());
  if (unlocked) await vault.unlock(MASTER_PASSWORD, MASTER_PASSWORD);
  return { directory, vaultPath, vault };
}

function makeEntry(overrides = {}) {
  return {
    site: 'example.com',
    username: 'alice',
    password: 'secret-password',
    notes: '',
    category: 'login',
    favorite: false,
    backupCodes: [],
    ...overrides
  };
}

module.exports = { MASTER_PASSWORD, createTempDirectory, createVault, makeEntry };
