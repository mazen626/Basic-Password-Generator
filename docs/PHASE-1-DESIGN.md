# Phase 1 Design: Security Foundation

**Status:** approved by the owner on 2026-11-10, including the four recommended decisions below. Each milestone still starts only when the owner asks for it.

**Based on:** `main` at version 1.1.2 plus the `phase-1-security` branch, reviewed on 2026-11-10. See [DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md) for the Phase 1 goals and [SECURITY.md](SECURITY.md) for the current model.

## Goal and threat

Phase 1 limits how much secret data the app window (the renderer) holds, and makes saves and password changes fail safely.

**What it defends against:** a compromised or buggy window. The window displays content from vault entries and imported CSV files. CSP, sandboxing and `textContent` rendering already make script injection unlikely. If it happens anyway, this design limits what the attacker can reach.

| Today, a compromised window can... | After Phase 1, it can only... |
| --- | --- |
| Read every password and backup code, all held in memory from unlock | Read secrets the user reveals, one entry at a time |
| Copy any text to the clipboard after one confirmation | Copy the specific entry the confirmation dialog named |
| Read nothing else on disk | No change |

**What it does not defend against:** malware running as the same Windows user, keyloggers, or memory dumps of the main process. This matches the threat model in `SECURITY.md`.

## Current state

| Plan step | Status |
| --- | --- |
| 1. Threat model and IPC review | This document |
| 2. Copy by entry ID | Not done. `vault:copy-password` takes plaintext. |
| 3. Window receives metadata only | Not done. `vault:load-entries` returns every password and backup code. |
| 4. Durable saves | Mostly done: temp file in the same folder, rename, queued writes, recovery tests. Missing: flush to disk before the rename. |
| 5. Change master password | Not done. |
| 6. Security-path tests | Vault-level locked and interrupted-write cases are tested. Nothing tests `main.js`. |

Already in place and kept as is:
- Context isolation, sandbox, no Node integration, strict CSP, blocked navigation and new windows.
- Caller (sender frame) checks on every IPC channel.
- Idle lock, clearing renderer state on lock, and the 10-second clipboard clear.

## IPC review

Every channel in `preload.js`, and the secrets it carries today:

| Channel | Window sends | Window receives | Secret exposure today | Phase 1 change |
| --- | --- | --- | --- | --- |
| `vault:status` | none | exists, legacy, corrupted | none | none |
| `vault:unlock` | master password, confirmation | created, migrated | Master password crosses IPC as a string (unavoidable) | none |
| `vault:lock` | none | success | none | none |
| `vault:activity` | none | success | none | none |
| `vault:backup` | none | backup file name | none | none |
| `vault:open-folder` | none | success | none | none |
| `vault:load-entries` | none | **every entry, including passwords and backup codes** | High | Return metadata only |
| `vault:save-entry` | full entry, including password and codes | success | The window holds the new password anyway (it generated it) | none |
| `vault:update-entry` | full entry, including password and codes | success | The window must load the password to submit an edit | Password and codes optional: omitted means unchanged |
| `vault:set-backup-code-used` | entry ID, code ID, used | success | none | none |
| `vault:delete-entry` | entry ID | success | none | none |
| `vault:confirm-copy` | none | one-time token | The token isn't tied to any entry | Takes an entry ID and names the site in the dialog |
| `vault:copy-password` | **plaintext password**, token | success | Medium | Replaced by copy by entry ID |
| `vault:import-csv` | none | counts only | none: the file is read in the main process | none |
| `vault:export-csv` | none | count, file name | none: written in the main process after two native dialogs | none |
| `window:menu-action` | action name | success | none | none |
| `vault:auto-locked` (event) | none | none | none | none |

## Design

### A. Metadata-only loading

`vault:load-entries` returns, for each entry:

```
id, site, username, notes, category, favorite, createdAt, updatedAt,
hasPassword: true,
backupCodes: { total, unused }
```

Passwords and backup code values are never included. New channels provide them on request:

| Channel | Returns | Used by |
| --- | --- | --- |
| `vault:reveal-password` (entry ID) | That entry's password | The Reveal button, and the edit form's Show password button |
| `vault:get-backup-codes` (entry ID) | `[{ id, code, used }]` for that entry | Show codes, and the edit form's code list |

Each new channel requires an unlocked vault and a valid entry ID, and resets the idle timer.

**Renderer rules:**
- Revealed values live only in the entry card or edit form that asked for them. They are not stored in `savedEntries`.
- Hiding the value, re-rendering the list, or locking drops the value.
- Lock and auto-lock already replace the list and clear `savedEntries`, so revealed values go with them.

**Edit form:** the password field starts empty, with the hint "Leave blank to keep the current password". A **Show** button reveals the current password into the field. Saving with the field blank keeps the current password, so editing only the notes never loads the password into the window.

### B. Copy by entry ID

```
vault:confirm-copy-entry (entryId)        -> dialog: "Copy the password for github.com?" -> token
vault:copy-entry-password (entryId, token) -> main reads the password and writes the clipboard
```

- The token is tied to that entry ID, expires after 30 seconds, and works once.
- The dialog text comes from the main process, so the user sees which site is being copied.
- The existing digest check and the 10-second clipboard clear stay as they are.

**Generated passwords** (the generator's Copy button) are created in the window and aren't in the vault yet, so that path keeps sending text. It moves to its own channel, `vault:copy-generated`, with its own confirmation that says "generated password". Only the generator calls it.

### C. Durable saves

```
open vault.json.tmp -> write -> FileHandle.sync() -> close -> rename over vault.json
```

- `sync()` calls `FlushFileBuffers` on Windows, so the new file is on disk before it replaces the old one.
- **Windows limitation:** Windows can't flush a folder, so a power cut right after the rename could, rarely, still lose that rename. In that case the previous `vault.json` is still intact. This will be documented.
- The existing `.tmp` cleanup, size limit and write queue stay.

### D. Change master password

A File menu item opens a form with current password, new password and confirmation. Channel: `vault:change-master-password (current, next, confirmation)`.

Main-process steps, all inside the write queue:
1. Require an unlocked vault, and validate the new password with the existing rules (8 to 1024 characters, matching confirmation, different from the current one).
2. Verify the current password by deriving a key from the vault's salt and decrypting. Failure leaves everything untouched.
3. Save a byte-for-byte backup of the current file as `vault-backup-<timestamp>-<id>.bak`.
4. Generate a new salt, and derive the new key with the current `PBKDF2_ITERATIONS` (600,000). Vaults created with fewer iterations are upgraded this way.
5. Re-encrypt every entry, validate the result, write it using the durable save from part C, then swap the in-memory key.
6. On any failure before the rename, the old file and old key stay in use. After the rename, the new file is complete and validated.

**Old backups keep the old password.** The form will say so, because restoring an older backup needs the password that was current when it was made.

### E. Deny Electron permissions

Set `setPermissionRequestHandler` to always deny, and `setPermissionCheckHandler` to return false. The app uses no camera, microphone, notifications or similar. Copying goes through the main process, so it doesn't need clipboard permission.

### F. Testable IPC layer

`main.js` handlers can't be unit-tested today. Move the handler logic into `ipc-handlers.js`, which receives `vault`, `clipboard`, `dialog`, timers and a frame-check function as inputs. `csv-transfer.js` already does this with `registerCsvHandlers`. `main.js` keeps the Electron wiring only.

New tests (Node's built-in runner, fake clipboard and dialog, `mock.timers`):
- Calls from the wrong frame are rejected on every channel.
- Locked-vault calls are rejected, along with malformed or unknown IDs and wrong types.
- Copy:
  - A token without a confirmation, a reused token, an expired token, or a token for a different entry is refused.
  - The clipboard clears after 10 seconds only if it still holds the copied password.
- `vault:load-entries` responses never contain a `password` or `code` field.
- Password change fails safely: a wrong current password, an interrupted write, or a validation failure all leave the old vault and key in use. Success opens with the new password and not the old one.
- Permission handlers deny.

Renderer behavior is checked with a scripted run of the real app against a throwaway vault, like the backup-codes check. That script isn't part of `npm test`.

## Compatibility

- **No vault format change:** the file stays at version 3 with the same entry schema, so no migration is needed. Versions 1 to 3 still open.
- **`preload.js` API change:** `copyPassword(password, token)` is removed. It's replaced by `confirmPasswordCopy(entryId)`, `copyEntryPassword(entryId, token)` and `copyGeneratedPassword(text, token)`. `revealPassword(id)`, `getBackupCodes(id)` and `changeMasterPassword(...)` are added. Only `renderer.js` uses this API.
- **`updateEntry`:** existing calls that send the password still work. Omitting it is new.
- **CSV:** import and export already run in the main process, so they're unaffected.

## Delivery plan

One PR per milestone, each with full `npm test` passing and `SECURITY.md` updated:

| Milestone | Contents | Behavior change |
| --- | --- | --- |
| 1.1 | Part F (testable IPC layer and tests for today's behavior) and part E (deny permissions) | Permissions are denied. Otherwise none. |
| 1.2 | Parts A and B (metadata-only load, reveal and codes by ID, copy by ID, edit without plaintext) | Yes |
| 1.3 | Part C (durable saves) | None visible |
| 1.4 | Part D (change master password) | New feature |

1.1 comes first so 1.2 changes behavior with tests already in place.

## Owner decisions (approved 2026-11-10)

1. **Notes:** stay in the metadata. **Decided: yes.**
   - **Recommendation:** keep them for now, so search still covers notes.
   - **Why:** making notes secret would mean either dropping them from search or moving search into the main process.
   - **Implication:** notes then need to be documented as not-secret, and users should keep secrets in the password or backup-code fields.
2. **Copying generated passwords:** the generator's Copy button keeps sending text, as in part B. **Decided: yes.**
   - **Recommendation:** yes. The password is created in the window, so the window already has it.
3. **Reveal confirmation:** Reveal doesn't ask for confirmation. **Decided: same as today.**
   - **Recommendation:** no, the same as today. Copy keeps its confirmation, because the clipboard is shared with other apps.
4. **Old backups after a password change:** keep them, opening with the old password. **Decided: yes, with a note in the form.**
   - **Recommendation:** yes, with a note in the form. Re-encrypting or deleting backups belongs to Phase 2A.

## Out of scope

- Backup pruning and restore screens (Phase 2A).
- Keeping the master password out of IPC: it has to be typed in the window.
- Zeroing JavaScript strings. This can't be done reliably, so `SECURITY.md` will keep saying so.
- Updating `DEVELOPMENT_PLAN.md`'s "v1/v2 vaults" wording to version 3. That fits in milestone 1.1.
