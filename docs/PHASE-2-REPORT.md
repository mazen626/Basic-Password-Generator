# Phase 2 Progress Report

A short report is added here after each Phase 2 milestone: what changed, what is now implemented, how it was checked, and what is still open. The newest milestone is at the top.

Plan: [DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md) (Phase 2: 2A backups and restore, 2B record types, 2C import and export). Design: [PHASE-2A-DESIGN.md](PHASE-2A-DESIGN.md).

## 2A.1: Backup list (version 1.4.0, 2026-11-12)

**What changed**
- New **File > Backups…** window. It lists every backup next to the vault with its date, kind, size, status (OK, too large, damaged or not a backup, can't be read) and a password hint (current password, or may need an earlier one). "Create backup now" makes a new backup and refreshes the list.
- Backups made before a master-password change are now named `vault-before-password-change-*`, and those made before a CSV import `vault-before-import-*`, so the list can say why each one exists. Existing files keep their names.
- `docs/SECURITY.md` has a new "Backups" section, and its version 3 format example now correctly shows `"version": 3`. The README lists the new backup names.

**What is implemented**
- The backup list is read only: it never decrypts, changes or deletes a file. It works whether the vault is locked or unlocked.
- Only files whose names exactly match the app's backup patterns are listed. Folders, symlinks and junctions are skipped, and files over 8 MB are reported without being read.
- The window names a backup only by its file name, never a path, and receives at most 1,000 items, with valid backups first.

**Checks**
- `npm test`: 163 tests, 162 pass, 0 fail, 1 skipped. The skipped test needs a file symlink, which this Windows account isn't allowed to create; a junction test covers the same path.
- Code reviewed against the approved design (parts A, B and F).
- Not yet checked by hand in the running app.

**Still open**
- A file that can't be inspected for a reason other than "missing" is listed with size 0.
- Restore and cleanup are not implemented yet.

**Next:** 2A.2, restore preview: pick a backup, type its password, and see its entry count without changing anything.

## 2A.0: Backup and restore design (version 1.3.3, 2026-11-12)

**What changed**
- Added [PHASE-2A-DESIGN.md](PHASE-2A-DESIGN.md), the design for listing, previewing, restoring and deleting encrypted backups. It had an independent security review, all of whose required changes are included, and the owner approved it with six decisions on 2026-11-12.
- Added milestone **2C, import and export compatibility**, to `DEVELOPMENT_PLAN.md` and the README roadmap. It covers CSV files from and for browsers (Chrome, Edge, Brave, Firefox, Safari) and password managers (Bitwarden, 1Password, LastPass, Proton Pass, KeePass, Dashlane and others).
- The README now gives VLAUTR as the project's official name.

**What is implemented**
- Nothing in the app yet. This milestone is design and planning only, with no code changes.

**Decisions approved**
1. Backups are never deleted automatically; the user chooses what to delete.
2. A restored vault keeps the backup's master password, and the form says so.
3. Pre-upgrade backups are listed and labeled.
4. List, preview and restore work while the vault is locked; deleting needs it unlocked.
5. New backups made before a password change or a CSV import get names that say so.
6. Deleting a backup is permanent (not the Recycle Bin), and the confirmation says so.

**Checks**
- Design claims checked against `vault.js`, `ipc-handlers.js` and `csv-transfer.js`.
- `npm test` was not rerun: no code changed since version 1.3.2, where all 143 tests passed.

**Still open**
- `docs/SECURITY.md` shows `"version": 2` in its version 3 format example. It will be fixed with 2A.1.

**Next:** 2A.1, a read-only backup list.
