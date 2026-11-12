# VLAUTR Security Model

This document describes how VLAUTR protects vault data today: what it guarantees, what it doesn't, and the known gaps scheduled for Phase 1. It reflects the code as of Phase 1 (`vault.js`, `ipc-handlers.js`, `main.js`, `preload.js`, `renderer.js`, `page.html`).

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
  "version": 3,
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
| Main (`main.js`, `ipc-handlers.js`, `vault.js`) | Derived key, vault file, clipboard, dialogs | All vault operations run through `registerVaultHandler` in `ipc-handlers.js`, which rejects calls from any frame other than the app's own `page.html` and serializes operations. Every Electron permission request and check is denied. `test/ipc-handlers.test.js` covers the caller checks, locked-vault calls, copy tokens, clipboard clearing, idle lock, menu actions and permissions. |
| Preload (`preload.js`) | `ipcRenderer` | Exposes a fixed `window.electronAPI` surface only. |
| Renderer (`renderer.js`, `page.html`) | Entry metadata after unlock: site, username, notes, category, favorite, dates, and backup code counts. A password or an entry's codes only after the user presses Reveal, Show codes, or Show in the edit form | `sandbox: true`, `contextIsolation: true`, `nodeIntegration: false`. The CSP allows only local scripts, styles, and fonts. Navigation and new windows are blocked. Entry data is rendered with `textContent`, never `innerHTML`. Revealed values are kept only by the card or form that asked for them, and are dropped on hide, re-render or lock. Notes are treated as metadata so they stay searchable; keep secrets in the password or backup code fields. |

## Session behavior

- **Locking:** manual, from the File menu, after 5 minutes without activity, when the window closes, and on quit. Locking zeroes the key buffer.
- **Activity:** the renderer reports activity at most once every 30 seconds, so auto-lock happens between 4.5 and 5 minutes after the last real input. Resuming from sleep or unlocking the screen re-checks the idle timer, but it does not lock immediately.
- **Copying:** a native confirmation dialog issues a one-time token that is valid for 30 seconds and tied to what it was confirmed for. For a saved entry, the dialog names the site, the window sends only the entry ID, and the main process reads the password from the vault. The generator's Copy button sends the generated password, which the window created, with its own token. If the vault locks while the dialog is open, no token is issued. The clipboard is cleared after 10 seconds if it still holds the copied password (compared by SHA-256), and again on quit.

## CSV import and export

Both run from the File menu and only while the vault is unlocked. The page asks for "import" or "export" and nothing else: it never supplies a file path and never sees CSV text. The main process (`csv-transfer.js`) opens the native file dialogs and confirmation boxes itself, so page code cannot click through them. What goes back to the page is counts, row numbers, column names, and a file name; never passwords or file content.

**Import** (`csv-transfer.js`)

- The file must be UTF-8 or UTF-16 text of at most 5 MB and 10,000 rows. Every row passes the same `validateEntry` rules as an entry typed in by hand.
- Nothing is written until the person confirms. Then an encrypted backup of the vault is made, and all new entries are added in one write transaction, so a failure leaves the vault unchanged. Existing entries are never overwritten.
- The raw file bytes are zeroed once parsed. The decoded text and entry strings are ordinary JavaScript strings and cannot be zeroed.
- "Import and delete" removes the CSV only after the import succeeded. It is a plain delete, not a secure wipe.

**Export** (`csv-transfer.js`) is a deliberate exception to the rule that plaintext never reaches disk: the person asked for a readable copy of their vault, so every password is written unencrypted.

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

## Backups

Backups are byte-for-byte copies of `vault.json`, written next to it with `wx` and flushed to disk. They open with the master password that was in use when they were made. Names say why each one was made:

| Name | Made by |
| --- | --- |
| `vault-backup-<ms>-<uuid>.bak` | "Create backup" (and, up to version 1.3.4, password changes and CSV imports) |
| `vault-before-password-change-<ms>-<uuid>.bak` | Change master password (from version 1.4.0) |
| `vault-before-import-<ms>-<uuid>.bak` | CSV import (from version 1.4.0) |
| `vault.json.v<1\|2>-<ms>-<uuid>.bak` | Format upgrade on unlock |

**Backup list (Phase 2A milestone 2A.1).** File > Backups… shows the backups through `vault:list-backups`, which works locked or unlocked and is read only:
- Only top-level files whose names fully match the patterns above (lowercase-hex UUID, no case folding) are considered. Symlinks, junctions and folders are skipped.
- Files over 8 MB are listed as too large without being read. Others are read up to 8 MB and checked with the same envelope rules as the vault. No key is derived and nothing is decrypted.
- Each item shows its date (from the name), kind, size, status and a password hint. The hint compares the backup's salt and iteration count with the current vault: "current" is reliable, "other" means it may need an earlier master password. The salt itself is never sent to the window.
- The window refers to a backup only by its validated file name, never a path. It receives at most 1,000 items, valid ones first.

**Restore preview (2A.2).** "Preview…" on a valid backup asks for that backup's master password and calls `vault:preview-backup`, which works locked or unlocked:
- The backup is read with the same file rules as the list, decrypted in memory with a key derived from its own salt and iterations, and fully validated. Version 1 and 2 backups are also upgraded in memory as a dry run. Nothing is written, and the vault's own key and lock state are never used or changed.
- The derived key is zeroed afterwards. The window receives only the entry count, the newest and oldest entry dates, the format version and whether it will be upgraded: no entry data and no key settings. A wrong password and damaged contents give the same error.
- A successful preview issues a one-time restore token, valid for 2 minutes and held in the main process with the backup's SHA-256, the current vault file's SHA-256 and the summary. Lock, auto-lock, unlock, a password change, a CSV import, closing the app and any new preview cancel it.
- Decrypted entries are JavaScript strings during the preview and can't be zeroed, as with unlock.

**Restore (2A.3).** `vault:restore-backup(id, token)` works locked or unlocked, and from the unlock screen through "Restore from backup…":
1. The token is used up first, whatever happens next.
2. A native confirmation from the main process, with Cancel as the default, names the backup's date, kind and previewed entry count. It is built only from what the main process stored at preview, so the window can't make it describe another backup.
3. If the vault was locked, unlocked, or any cancel event happened while the confirmation was open (including auto-lock), the restore stops.
4. Inside the vault's write transaction, so no other save can run in between: `vault.json` is read once and must match the state recorded at preview; the backup is read again and must match the previewed SHA-256; a backup identical to the current vault is refused.
5. The current vault is saved as `vault-before-restore-<ms>-<uuid>.bak` (never overwriting a file), flushed, and read back to check its SHA-256. If that fails, nothing is restored.
6. The backup's exact bytes replace `vault.json` through the same `.tmp` + flush + rename path as every save, then the vault locks. It opens with the master password that was in use when the backup was made; version 1 and 2 backups are upgraded on that unlock as usual.

Any failure before the rename leaves `vault.json` and the lock state unchanged. Same limit as every save: Windows can't flush the folder, so a power cut right after the rename can lose the rename, leaving the previous vault in place.

**Cleanup (2A.4).** Backups are never deleted automatically. In File > Backups…, opened while unlocked, the user selects backups and chooses "Delete selected…"; `vault:delete-backups(ids)` needs the vault unlocked:
- The ids are checked (1 to 1000, unique, each a valid backup name) and compared with a fresh, uncapped scan of the folder. If any is missing, nothing is deleted.
- A native confirmation built from that scan says "Permanently delete N backups from <date> to <date>? This can't be undone." Cancel is the default. If the vault locks or any cancel event happens while it is open, nothing is deleted.
- Inside the vault's write transaction, a second fresh scan decides which backups are protected. These are never deleted, even when selected: the newest valid backup (so a valid backup always remains), the newest valid backup that opens with the current master password, and the newest valid pre-restore backup (or the newest pre-restore file if none is valid). They are reported back with the reason.
- Each other file is deleted with a plain `unlink`, only if it is still a regular file in the vault folder. There is no Recycle Bin and no secure wipe: copies may survive in File History, shadow copies, cloud sync or on SSD blocks, still encrypted with the password they were made with.
- "Valid" means the file's structure is correct. The app can't confirm a backup decrypts without its password, so the guards protect structurally valid files, not ones known to open.

## Known gaps (planned for Phase 1)

1. **Plaintext in the renderer (fixed in Phase 1 milestone 1.2).** `vault:load-entries` now returns metadata only. A password or an entry's codes reach the renderer only through `vault:reveal-password` or `vault:get-backup-codes`, one entry at a time, when the user asks. Values that have been revealed stay in renderer memory until garbage collected, and JavaScript can't zero them.
2. **Copy takes plaintext (fixed in Phase 1 milestone 1.2).** Copying a saved entry sends only its ID with a token tied to that entry. The generator's Copy button still sends text, because the window created that password.
3. **Master password in IPC.** The master password crosses IPC as a JavaScript string, which can't be zeroed. Only the derived key buffer is zeroed.
4. **Write durability (fixed in Phase 1 milestone 1.3).** Each save writes `vault.json.tmp`, flushes it to disk (`FileHandle.sync()`, which is `FlushFileBuffers` on Windows), and only then renames it over `vault.json`. A power cut can no longer leave a renamed but unwritten vault. Backup files are flushed to disk the same way. Remaining limit: Windows cannot flush a folder, so a power cut right after the rename can lose the rename, leaving the previous vault in place.
5. **Backups are never pruned** and stay readable with the master password that was in use when they were created. Since Phase 2A they can be listed, restored and deleted by hand; old backups made under a leaked password should be deleted once a newer backup exists.
6. **File permissions.** `mode: 0o600` has no effect on Windows; the vault inherits the default ACL of `%APPDATA%`.
7. **Permissions (fixed in Phase 1 milestone 1.1).** `denyAllPermissions` in `ipc-handlers.js` now denies every Electron permission request and check, such as camera, microphone and notifications. The app needs none of them.
8. **Master-password change (fixed in Phase 1 milestone 1.4).** File > Change master password checks the current password, saves a byte-for-byte backup, then re-encrypts the vault with a fresh salt and 600,000 iterations, which also upgrades vaults created with fewer. A failure before the rename leaves the old vault and key in use. Backups made before the change still open only with the old password.
9. **Plaintext CSV files.** An exported CSV, and a CSV that is imported but not deleted, hold every password unencrypted for as long as they exist. See [CSV import and export](#csv-import-and-export).

## Reporting

There is no formal disclosure process yet. Report security issues privately to the repository owner rather than in a public issue.
