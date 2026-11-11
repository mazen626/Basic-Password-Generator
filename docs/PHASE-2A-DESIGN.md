# Phase 2A Design: Backup and Recovery Management

**Status:** approved by the owner on 2026-11-12, after an architect review. Nothing here is implemented yet. Each milestone starts only when the owner asks for it.

**Based on:** `main` at version 1.3.2 (commit 824d4cd), reviewed on 2026-11-12. See [DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md) for the Phase 2A goal and acceptance criteria, and [SECURITY.md](SECURITY.md) for the current model.

## Goal and threat

Phase 2A lets users see, restore and clean up their encrypted backups from inside the app, without ever risking the active vault.

**What it defends against:**
- Losing data through a bad restore: a damaged, truncated, unrelated or wrong-password file must never replace `vault.json`.
- Losing data through a restore that turns out to be the wrong one: the current vault is always saved first.
- A compromised window: it can name a backup by file name only, never a path. It can't skip the native confirmations for restore and delete, or choose what they say.
- Silent loss of backups: nothing is deleted without the owner choosing it and confirming it.

**What it does not defend against:** the same things as today (malware running as the same Windows user, keyloggers, memory dumps of the main process). Anyone who can read the vault folder can also copy the backups and guess their passwords offline, just as with `vault.json`.

## Current state

| Item | Today |
| --- | --- |
| Manual backup | "Create encrypted backup" on the unlock screen (not in the File menu). `vault:backup` works while locked. Writes `vault-backup-<ms>-<uuid>.bak`. |
| Before a master-password change | `writeBackup` in `changeMasterPassword`. Same name pattern as manual. |
| Before a CSV import | `csv-transfer.js` calls `vault.createBackup()`. Same name pattern as manual. |
| Before a format upgrade | `backupLegacyVault` writes `vault.json.v<1|2>-<ms>-<uuid>.bak`. |
| How they are written | Exact bytes of `vault.json`, opened with `wx`, flushed with `FileHandle.sync()`. |
| List, restore, delete | None. The user can only open the folder (`vault:open-folder`, which also works while locked). |

Three different sources produce the same `vault-backup-*` name, so manual, pre-password-change and pre-import backups **can't be told apart** for existing files. Only pre-upgrade backups have their own pattern.

`vault:status` reports a vault as corrupted only when it is too large, isn't JSON, or fails the envelope check. Damaged ciphertext inside a valid envelope looks healthy until unlock fails.

Reused as is: `validateEnvelope`, `decodeBase64`, `decryptEntries` (zeroes its plaintext buffer), `validateEntries`, `validateLegacyEntries`, `migrateEntries`, `deriveKey`, `writeAndFlush`, the `.tmp` + flush + rename path in `writeVaultFile`, `runWriteTransaction`, `registerVaultHandler` (caller check plus serialization) and the 8 MB `MAX_VAULT_BYTES` limit.

## Design

All file work lives in `vault.js` (a few new methods on `PasswordVault`). `ipc-handlers.js` adds channels, tokens and native dialogs. The window only shows results.

### A. Backup names and kinds

Recognized names in the vault folder, and nothing else:

| Pattern | Kind shown | Made by |
| --- | --- | --- |
| `vault-backup-<13 digits>-<uuid>.bak` | Backup | Manual, and (in 1.3.2 and earlier) password change and CSV import |
| `vault.json.v<1|2>-<13 digits>-<uuid>.bak` | Pre-upgrade | Format upgrade on unlock |
| `vault-before-restore-<13 digits>-<uuid>.bak` | Pre-restore | 2A.3 (new) |
| `vault-before-password-change-<13 digits>-<uuid>.bak` | Pre-password-change | 2A.1, if decision 5 is approved |
| `vault-before-import-<13 digits>-<uuid>.bak` | Pre-import | 2A.1, if decision 5 is approved |

- Each pattern is a full-match regular expression **without** the `i` flag. The UUID is lowercase hex only (`[0-9a-f]`), as `crypto.randomUUID()` writes it. Windows file names are case-insensitive, so this allows exactly one spelling per file.
- The `vault.json` part is built from `path.basename(this.filePath)` with regex characters escaped.
- `vault.json`, `vault.json.tmp` and every other file in `%APPDATA%\my-projects` (Electron's own caches and settings) never match.
- The backup date is the millisecond timestamp in the name, which the app wrote. File times can change when files are copied, so they are not used.

### B. Inventory (2A.1)

`vault.listBackups()`:

1. `readdir` the vault folder (top level only). Keep names that match a pattern.
2. `lstat` each one. Skip anything that is not a regular file: symlinks, junctions and folders are not listed at all.
3. If the size is over 8 MB, list it with status **Too large** and don't read it.
4. Otherwise read it, stopping at 8 MB + 1 byte. Swapping the file between `lstat` and the read would take code running as the same Windows user, which is out of scope.
5. Parse it and run `validateEnvelope`. No key is derived and nothing is decrypted.
6. A file that disappears during the scan (`ENOENT`) is left out. One that can't be read for another reason is listed as **Unreadable**. Either way the scan carries on.

Each item returned:

```
id           the validated file name (e.g. "vault-backup-1762900000000-<uuid>.bak")
kind         backup | pre-upgrade | pre-restore | pre-password-change | pre-import
createdAt    ISO date from the name
size         bytes
version      1, 2 or 3 (valid files only)
status       valid | too-large | invalid | unreadable
passwordHint current | other | unknown
```

- **Status:** a file is **invalid** if it fails parsing or the envelope check, or if its version doesn't match the `v<N>` in a pre-upgrade name. Invalid files are listed so the user can see and remove them, but they can't be previewed or restored.
- **Password hint:** a password change always creates a new salt. If a backup's salt and iterations equal those of the current `vault.json`, it opens with the current master password (**current**). This is reliable.
  - Otherwise the backup "may need an earlier master password" (**other**). It can still open with the current password, for example after changing from A to B and back to A, or after a restore.
  - If `vault.json` is missing or invalid, the hint is **unknown**.
  - Only the hint is returned, never the salt.
- **Uncapped scan, capped list:** `vault:backup` works while locked and can be called over and over, so the folder can fill up.
  - The scan behind the restore and delete guards is never capped.
  - The list sent to the window holds at most 1,000 items and then returns `truncated: true`. Valid items come first, newest first. Invalid ones only fill the places left, so junk files can't push real backups off the list.

**How the window refers to a backup:** by the file name in `id`, never a path. Every call that takes an `id` checks it against the patterns again (they allow no separators, `..` or drive letters), joins it to the vault folder, and repeats steps 2 to 5. There is no ID table in memory, so nothing goes stale after a restart or a re-scan.

### C. Restore preview (2A.2)

`vault.previewBackup(id, password)`:

1. Check the `id` and read the file as in part B. Keep the bytes and their SHA-256 digest.
2. Derive the key from the backup's salt and iterations, and decrypt. Version 1 and 2 entries also go through `migrateEntries` and `validateEntries` in memory, so a backup that would fail its later upgrade is rejected now.
3. A wrong password or tampered data gives the usual message: "Incorrect password, or the backup is damaged." Nothing is written in any case.
4. Return a summary with metadata only: entry count, newest entry `updatedAt`, oldest `createdAt`, format version, and whether it will be upgraded on unlock. No site names, usernames or other entry data.

**Dropping secrets:** the derived key is zeroed in a `finally` block, and `decryptEntries` already zeroes the plaintext buffer. The decrypted entries are plain JavaScript strings. They become unreachable when the call returns, but they can't be zeroed, as `SECURITY.md` already says for the main vault.

**Restore token:** on success, `ipc-handlers.js` issues a one-time token, valid for 2 minutes, in the same way as copy tokens. The token is stored with:
- the backup `id` and the SHA-256 of its bytes;
- the vault state: the SHA-256 of the current `vault.json` bytes, or "absent";
- whether the vault was locked or unlocked;
- the preview summary and the date from the file name, for the confirmation in part D.

These cancel the token: lock, auto-lock, unlock, a new preview, a master-password change, a CSV import, `shutDown`, and any failed restore. The password is not kept and not sent again.

**Unlocked first?** No. Preview and restore work whether the vault is locked or not, gated by the backup's password (decision 4).

### D. Transactional restore (2A.3)

`vault:restore-backup(id, token)`:

1. Check the token against `id` and **use it up** before showing anything, whatever happens next.
2. Show a native confirmation (default button: Cancel). It is built only from the data stored with the token: "Replace the current vault with the backup from 12 Nov 2026, 14:03 (214 entries)? A copy of the current vault is saved first." Cancel returns `{ cancelled: true }` and changes nothing.
3. After the dialog, check two things, because the idle lock can fire while the dialog is open (`confirmCopy` handles the same case): the vault is still locked or unlocked as it was when the token was issued, and no cancel event happened meanwhile (a counter that every cancel event increases). If either changed, stop.
4. Inside `runWriteTransaction`:
   - Read the backup again (part B), run `validateEnvelope`, and require its SHA-256 to equal the previewed digest.
   - Read `vault.json` **once**, and require its digest (or "absent") to equal the vault state stored with the token.
   - Any change since the preview fails here. From this point the app uses only these bytes in memory.
   - Refuse if the backup bytes equal the current vault: "This backup is the same as the current vault."
5. If `vault.json` exists, save the pre-restore copy as `vault-before-restore-<ms>-<uuid>.bak` (flushed, `wx`):
   - Normally it is written from the bytes read in step 4.
   - A vault over 8 MB isn't held in memory. It is copied with `copyFile` (`COPYFILE_EXCL`, then open and `sync`), and its digest is computed by streaming the file.
   - Read the copy back and check its SHA-256. If any part of this fails, stop: `vault.json` is untouched.
6. Write the backup bytes to `vault.json.tmp`, flush, and rename over `vault.json`. This reuses `writeVaultFile`'s path, split so it can take raw bytes (`writeVaultBytes`) instead of an envelope object.
7. Lock the vault (zero the key), cancel copy and restore tokens, and return `{ success, restoredFrom, preRestoreBackup }`. The window shows the unlock screen.

**State after restore:** locked. The unlock screen says: "Backup from 12 Nov 2026 restored. Unlock with the master password that was in use when it was made. Your previous vault was saved as a pre-restore backup." Staying unlocked would mean keeping the backup's derived key from the preview, which part C deliberately drops.

**Legacy backups:** restored byte for byte, so `vault.json` becomes version 1 or 2 again. The next unlock upgrades it exactly as today. That upgrade makes its own `vault.json.v<N>-*.bak` copy, a harmless duplicate of the restored backup.

**Failures:**

| When | Result |
| --- | --- |
| Before step 5 (cancel, bad token, auto-lock during the dialog, changed backup or vault, read error) | Nothing written. Vault state unchanged. The token is already used up, so the user previews again. |
| Step 5 fails, or the copy's digest doesn't match | `vault.json` untouched. The app tries to remove a partly written pre-restore file; if one remains, it is listed as invalid. |
| Step 6 fails before the rename | `.tmp` removed, `vault.json` unchanged, pre-restore backup kept. The vault stays unlocked if it was. |
| Crash or power cut during step 6 | Same as any save today: either the old `vault.json` or the complete new one. The pre-restore backup is already on disk. |
| After the rename | The restore is complete. Locking can't fail. |

### E. Retention (2A.4)

Manual only (decision 1): the user selects backups and deletes them.

- `vault:delete-backups(ids)` first shows a native confirmation: "Permanently delete 12 backups from 3 Jan 2026 to 9 Oct 2026? This can't be undone." The deletion then runs inside `runWriteTransaction`.
- The guards come from a fresh, uncapped scan made at that moment, never from the window. If any `id` is not in that scan, the whole request is refused.
- The guards are checked against what would be left after the deletion, so deleting several files at once can't get round them. These must remain:
  - the newest **valid** backup, so at least one valid backup always remains;
  - the newest backup whose hint is **current**, if there is one;
  - the most recent pre-restore backup.
- Protected files are skipped and reported back (`kept: [{ id, reason }]`). Invalid, too-large and unreadable files can be deleted.
- Deletion is a permanent `fs.unlink` of an encrypted file: no Recycle Bin, no secure wipe. Copies may survive in File History, shadow copies, OneDrive or on SSD blocks, still encrypted with the password they were made with.
- "Valid" means the envelope is correct. The app can't confirm that a backup decrypts without its password, so the guards protect the newest structurally valid file, not one known to open.
- Manual cleanup needs no setting, so there is no new data location.

### F. IPC and preload

All channels use `registerVaultHandler` (caller check plus serialization). Each calls `armIdleLock()` after success when the vault is unlocked.

| Channel | Arguments and checks | Unlock needed | Returns |
| --- | --- | --- | --- |
| `vault:list-backups` | none | No | items from part B, `truncated` |
| `vault:preview-backup` | `id`: string ≤ 128 characters, matches a pattern; `password`: string, 1–1024 characters | No | summary, token |
| `vault:restore-backup` | `id` as above; `token`: string UUID | No | `restoredFrom` and `preRestoreBackup`, or `cancelled` |
| `vault:delete-backups` | `ids`: array of 1–1000 unique valid `id` strings | Yes | `deleted` and `kept`, or `cancelled` |

- **No separate recovery mode.** `vault:status` can't tell a healthy vault from one with damaged ciphertext. So list, preview and restore always work, locked or not. They are gated by the backup's password, the native confirmation and the pre-restore copy. Delete always needs the vault unlocked.
- The lock, auto-lock, unlock, change-master-password and import-csv handlers, and `shutDown`, all cancel any restore token.
- Preload adds exactly `listBackups()`, `previewBackup(id, password)`, `restoreBackup(id, token)` and `deleteBackups(ids)`. Nothing generic.
- Error messages follow the existing style: no paths, no ciphertext.

### G. Screens

Same dark-purple theme, IBM Plex Sans for text, IBM Plex Mono for file names and sizes, and the existing `<dialog>` pattern used by "Change master password".

- **File > Backups…** (new menu item, enabled when unlocked) opens a dialog containing:
  - a list of backups showing date, kind, size, password hint and status (status as text and an icon, never colour alone);
  - "Create backup now" (the existing `backupVault`);
  - a checkbox on each row, and "Delete selected…";
  - "Restore…" on valid rows.
- **Restore step** (same dialog): the backup's date and kind, a password field, the note from decision 2, then **Preview**. The summary appears ("214 entries, last changed 3 Nov 2026"), followed by **Restore**, which opens the native confirmation.
- **Unlock screen:** the recovery area always shows "Restore from backup…" next to the existing backup and folder buttons. It opens the same dialog without the delete controls.
- Lock and auto-lock close the dialog and clear the password field, as `clearUnlockedView` already does for the password-change form.

## Tests

All tests use `createTempDirectory` and `createVault` from `test/helpers.js`. No real vault is used.

| Milestone | Cases |
| --- | --- |
| 2A.1 | Each pattern recognized and labeled. `vault.json`, `.tmp` and unrelated `.bak`/`.json` files ignored. A symlink or folder with a matching name skipped. An oversized file reported without being read. Truncated, non-JSON, wrong-version, bad-base64 and wrong-length files marked **invalid**, as is a version that doesn't match the `v<N>` name. Password hint current, other and unknown. File removed mid-scan. Path-like, `..`, uppercase-hex and over-long `id` values rejected. The list works while locked. Flooded folder (1,500 valid files plus junk): list truncated with `truncated: true`, valid items before invalid ones. |
| 2A.2 | The correct password gives the right counts for v1, v2 and v3 backups. Wrong password and tampered tag rejected. Entries that fail validation rejected. The response has no `site`, `password` or `code` field. `vault.json` and the backup are byte-identical after every case. A token is issued only on success. Preview works while locked. |
| 2A.3 | Successful restore: `vault.json` equals the backup bytes, the pre-restore backup equals the old bytes, the vault is locked, and it unlocks with the backup's password with entries that verify. Cancel. Missing, reused, expired and mismatched tokens. Backup changed after preview. `vault.json` changed between preview and restore. Auto-lock while the confirmation is open: nothing written, token gone. Token cancelled by a password change, a CSV import and a failed restore. Identical-to-current refused. Pre-restore write fails, or its digest doesn't match: stops before the rename. Temp write fails (fault injection as in `vault-durability.test.js`). Interrupted before the rename. Each failure leaves `vault.json` byte-identical and the key state unchanged. A vault with damaged ciphertext (valid envelope, one flipped byte) restored while locked. A legacy backup restored, then upgraded on unlock. Restore with no `vault.json`. |
| 2A.4 | Cancel deletes nothing. The newest valid, newest `current`-hint and newest pre-restore backups are kept and reported, including when all are requested together. Deleting every valid backup at once refused. An `id` missing from the fresh scan refuses the request. Guards correct in a flooded folder, beyond the display cap. Invalid files can be deleted. Locked calls refused. |
| IPC | Wrong frame rejected on all four channels. Argument types and lengths checked. Native dialogs faked as in `ipc-handlers.test.js`. |

## Compatibility

- **No vault format change.** `vault.json` stays version 3 with the same entry schema. Restore writes a backup's exact bytes, so versions 1 to 3 all work.
- **Existing backups stay usable** with the password they were made with, and are listed. Old `vault-backup-*` files are labeled "Backup" because their source isn't recorded.
- **New file names only:** `vault-before-restore-*`, plus two more prefixes with decision 5. Older app versions ignore all `.bak` files, so they are unaffected.
- **Preload API:** four functions added, none changed or removed.

## Delivery plan

One PR per milestone. Each has `npm test` passing and updates `SECURITY.md` (known gap 5, plus a new "Backups" section).

| Milestone | Contents | Behavior change |
| --- | --- | --- |
| 2A.1 | Parts A and B, `vault:list-backups`, read-only Backups dialog, kind-tagged names (decision 5) | New screen, read only |
| 2A.2 | Part C, `vault:preview-backup`, restore step up to the summary | Read only |
| 2A.3 | Part D, `vault:restore-backup`, "Restore from backup…" on the unlock screen | Restore |
| 2A.4 | Part E, `vault:delete-backups`, selection and delete | Deletion |

## Risks and limitations

- **Forgotten backup passwords.** A backup opens only with the master password in use when it was made. The password hint helps, but an old backup whose password is forgotten can't be restored or checked.
- **Old passwords live on.** Changing a leaked master password doesn't protect old backups. They still open with the leaked password until they are deleted.
- **Restoring loses newer changes** unless the user restores the pre-restore backup again. The confirmation says so.
- **Windows can't flush the folder,** so a power cut right after a rename can lose the rename, leaving the previous `vault.json` in place. Same limit as today.
- **Deletion is not secure erase,** and Windows backups or sync tools may keep copies.
- **Structural checks only** in the list: "valid" means the envelope is correct, not that anyone knows the password.
- **Plaintext in memory** during a preview, as during unlock. It can't be zeroed in JavaScript.
- **Restore while locked** lets anyone at the computer who knows a backup's password roll the vault back. Nothing is lost, because the current vault is saved first. The same person can already do this by hand through "Open vault folder".

## Owner decisions (approved 2026-11-12)

1. **Retention:** never delete automatically; manual cleanup only. **Approved by the owner on 2026-11-12.**
   - **Recommendation:** manual only.
   - **Why:** recoverability comes first. Keep-last-N would need a stored setting: the vault can't hold one without a format change, and storing it anywhere else adds a new data location. Automatic deletion could also remove the last backup that matches a password the user still remembers.
2. **Password after restoring an older backup:** the vault keeps that backup's password, with a note in the restore form. **Approved by the owner on 2026-11-12.**
   - **Recommendation:** keep it.
   - **Why:** restore stays a byte-for-byte copy with no re-encryption, so it can't corrupt data. The user can change the password afterwards with the existing form. Forcing a new password would turn restore into a re-encryption, with more points of failure.
3. **Pre-upgrade backups:** list `vault.json.vN-*.bak` files, labeled "Pre-upgrade". **Approved by the owner on 2026-11-12.**
   - **Recommendation:** yes.
   - **Why:** they are often the oldest copy, and the only one from before an upgrade. They restore through the normal upgrade on unlock.
4. **Restore while locked:** list, preview and restore work while locked, in all cases. Delete still needs the vault unlocked. **Approved by the owner on 2026-11-12.**
   - **Recommendation:** allow restore while locked.
   - **Why:**
     - The app can't reliably tell that a vault is damaged: damaged ciphertext looks healthy until unlock fails. A "damaged only" rule would block real recoveries.
     - Requiring unlock adds little protection: "Open vault folder" already lets anyone at the keyboard roll back by hand in Explorer.
     - The window can't cause the corruption that would make a restore necessary.
     - A rollback destroys nothing, because the current vault is saved first.
     - It also helps a user who forgot the current password but remembers an older one.
5. **Kind-tagged names for new backups:** password change and CSV import write `vault-before-password-change-*` and `vault-before-import-*`; manual backups keep `vault-backup-*`. **Approved by the owner on 2026-11-12.**
   - **Recommendation:** yes, in 2A.1.
   - **Why:** it's a one-line change per caller and lets the list say why each backup exists. Without it, only pre-upgrade and pre-restore backups are labeled. Existing files are not renamed.
6. **Delete method:** delete permanently, not to the Recycle Bin. The confirmation says "permanently" and "can't be undone". **Approved by the owner on 2026-11-12.**
   - **Recommendation:** permanent delete.
   - **Why:** it matches what the user asked for, can be tested without Electron's `shell`, and doesn't leave files in the Recycle Bin that the user thinks are gone. The native confirmation and the guards are the safety steps.

## Out of scope

- Re-encrypting old backups under the current password, or any change to the vault format.
- Backups in other folders, in folders the user chooses, or on removable or cloud storage.
- Scheduled or automatic backups, and any automatic deletion.
- Merging entries from a backup into the current vault (restore replaces it whole).
- Checking that a backup decrypts (with its password) before the delete guards count it as protected. A possible later improvement; 2A keeps structural checks only.
- Fixing the `SECURITY.md` format example, which shows `"version": 2` under "version 3". That belongs in the 2A.1 documentation update.
