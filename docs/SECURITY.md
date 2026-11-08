# VLAUTR Security Model

This document describes how VLAUTR protects vault data today: what it guarantees, what it doesn't, and the known gaps scheduled for Phase 1. It reflects the code as of Phase 0 (`vault.js`, `main.js`, `preload.js`, `renderer.js`, `page.html`).

## Summary

- One encrypted file per user profile. No servers, accounts, telemetry, or network access.
- The master password is never written to disk. A 256-bit key is derived from it with PBKDF2 and is kept only in the main process while the vault is unlocked.
- The whole entry list is encrypted as a single AES-256-GCM message, so any tampering is detected on decryption.

## Cryptography

| Item | Value | Where |
| --- | --- | --- |
| Key derivation | PBKDF2-HMAC-SHA256, 600,000 iterations, 32-byte output | `deriveKey`, `PBKDF2_ITERATIONS` in `vault.js` |
| Salt | 16 random bytes, created once with the vault and reused for its lifetime | `initialize` |
| Cipher | AES-256-GCM, 12-byte random IV per write, 16-byte tag | `encryptEntries` |
| Plaintext | `JSON.stringify(entries)` of the full entry array | `encryptEntries` |
| Accepted iterations on read | 100,000 to 2,000,000 | `validateEnvelope` |
| Randomness | Node `crypto.randomBytes` / `randomUUID` (main); Web Crypto `getRandomValues` with rejection sampling (generator) | `vault.js`, `renderer.js` |

A wrong master password and a modified ciphertext both fail GCM authentication. They produce the same error on purpose: "Incorrect master password or vault data is corrupted."

### Vault file format (version 3)

```json
{
  "version": 2,
  "kdf": "pbkdf2-sha256",
  "iterations": 600000,
  "cipher": "aes-256-gcm",
  "salt": "<base64, 16 bytes>",
  "iv": "<base64, 12 bytes>",
  "tag": "<base64, 16 bytes>",
  "ciphertext": "<base64>"
}
```

Each decrypted entry must have exactly these keys: `id` (UUID), `site`, `username`, `password`, `notes`, `category`, `favorite`, `backupCodes`, `createdAt`, `updatedAt`. `backupCodes` is a list of up to 50 `{ id, code, used }` objects, each code 1 to 128 characters, and is encrypted with the rest of the entry. Adding or removing a field requires a new format version and a migration. Version 1 vaults are migrated on unlock, after an automatic backup.

Versions 1 and 2 are upgraded to version 3 on unlock, after a byte-for-byte copy of the old file is saved as `vault.json.v<version>-<timestamp>-<id>.bak`. Upgrading is one-way: older app builds report a version 3 vault as corrupted. To go back, restore that backup by hand; anything changed after the upgrade is not in it.

## Process boundaries

| Process | Has access to | Notes |
| --- | --- | --- |
| Main (`main.js`, `vault.js`) | Derived key, vault file, clipboard, dialogs | All vault operations run through `registerVaultHandler`, which rejects calls from any frame other than the app's own `page.html` and serializes operations. |
| Preload (`preload.js`) | `ipcRenderer` | Exposes a fixed `window.electronAPI` surface only. |
| Renderer (`renderer.js`, `page.html`) | Decrypted entries after unlock | `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`. The CSP allows only local scripts, styles, and fonts. Navigation and new windows are blocked. Entry data is rendered with `textContent`, never `innerHTML`. |

## Session behavior

- **Locking:** manual, from the File menu, after 5 minutes without activity, when the window closes, and on quit. Locking zeroes the key buffer.
- **Activity:** the renderer reports activity at most once every 30 seconds, so auto-lock happens between 4.5 and 5 minutes after the last real input. Resuming from sleep or unlocking the screen re-checks the idle timer, but it does not lock immediately.
- **Copying:** a native confirmation dialog issues a one-time token that is valid for 30 seconds. The clipboard is cleared after 10 seconds if it still holds the copied password (compared by SHA-256), and again on quit.

## CSV import and export

Both run from the File menu and only while the vault is unlocked. The page asks for "import" or "export" and nothing else: it never supplies a file path and never sees CSV text. The main process (`csv-handlers.js`) opens the native file dialogs and confirmation boxes itself, so page code cannot click through them. What goes back to the page is counts, row numbers, column names, and a file name; never passwords or file content.

**Import** (`csv-import.js`)

- The file must be UTF-8 or UTF-16 text of at most 5 MB and 10,000 rows. Every row passes the same `validateEntry` rules as an entry typed in by hand.
- Nothing is written until the person confirms. Then an encrypted backup of the vault is made, and all new entries are added in one write transaction, so a failure leaves the vault unchanged. Existing entries are never overwritten.
- The raw file bytes are zeroed once parsed. The decoded text and entry strings are ordinary JavaScript strings and cannot be zeroed.
- "Import and delete" removes the CSV only after the import succeeded. It is a plain delete, not a secure wipe.

**Export** (`csv-export.js`) is a deliberate exception to the rule that plaintext never reaches disk: the person asked for a readable copy of their vault, so every password is written unencrypted.

- A native warning (default button: Cancel) comes first, then a native save dialog. A second warning appears if the chosen folder looks like OneDrive, Dropbox, Google Drive or iCloud. This is a best-effort check on folder names only.
- Entries are decrypted only after the last confirmation. If the vault auto-locks while a dialog is open, nothing is written.
- The file is created with mode `0o600`, which has no effect on Windows (see known gap 6). The write buffer is zeroed afterwards, but string copies in memory cannot be.
- Values are written exactly as stored. A leading `=`, `+`, `-` or `@` is not escaped, because that would change real passwords, so opening the file in Excel can treat such cells as formulas. Import it into another password manager instead.
- The file stays wherever it was saved until it is deleted. VLAUTR cannot protect it afterwards.

## Threat model

### In scope (defended)

| Threat | Mitigation |
| --- | --- |
| Someone copies the vault file (backup sync, a stolen disk image) | AES-256-GCM with a PBKDF2-derived key; nothing is stored in plaintext. Resistance to offline guessing depends on the master password's strength (minimum 8 characters, no strength rule yet). |
| The vault file is modified on disk | GCM authentication fails and the vault refuses to open; the file is never rewritten. |
| A malformed or oversized file | Strict envelope and entry validation, an 8 MB file limit, and a 10,000-entry limit. Status reports "corrupted" without changing the file. |
| A crash or failed write | Writes go to `vault.json.tmp`, then `rename` replaces the vault. A failed write leaves the previous vault intact. |
| Malicious content inside entry fields (script injection) | DOM is built with `textContent`, and the CSP forbids inline and remote scripts. |
| Someone walks up to an unattended, unlocked app | Idle auto-lock after 5 minutes; passwords stay hidden until revealed. |
| Clipboard leftovers | Confirmation before copying and a 10-second auto-clear. |

### Out of scope (not defended)

- Malware running as the same Windows user: keyloggers, memory readers, clipboard watchers, or anything that can attach to the process.
- Windows clipboard history (Win+V) and cloud clipboard sync, which can keep copied passwords after VLAUTR clears the clipboard.
- Weak master passwords against offline brute force.
- Physical attacks on an unlocked machine within the idle window.
- Forgetting the master password. There is no recovery mechanism by design.

## Known gaps (planned for Phase 1)

1. **Plaintext in the renderer.** `vault:load-entries` returns every decrypted password and backup code to the renderer, which keeps them in memory (`savedEntries`) until lock. "Hide" only affects what's displayed.
2. **Copy takes plaintext.** `vault:copy-password` receives the password from the renderer instead of an entry ID.
3. **Master password in IPC.** The master password crosses IPC as a JavaScript string, which can't be zeroed. Only the derived key buffer is zeroed.
4. **Write durability.** The temp-file-and-rename write does not `fsync` before renaming, so a power loss can still produce a truncated file. Phase 0 tests confirm that a truncated file is detected and never overwritten, but recovery is manual (restore a backup).
5. **Backups are never pruned** and stay readable with the master password that was in use when they were created.
6. **File permissions.** `mode: 0o600` has no effect on Windows; the vault inherits the default ACL of `%APPDATA%`.
7. **No permission request handler** is set on the Electron session (camera, notifications, and so on). The app never requests them, but nothing explicitly denies them.
8. **No master-password change** and no iteration upgrade path for existing vaults.
9. **Plaintext CSV files.** An exported CSV, and a CSV that is imported but not deleted, hold every password unencrypted for as long as they exist. See [CSV import and export](#csv-import-and-export).

## Reporting

There is no formal disclosure process yet. Report security issues privately to the repository owner rather than in a public issue.
