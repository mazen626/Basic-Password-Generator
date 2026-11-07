# Phase 0 Completion Report

**Status:** accepted by the project owner on 2026-11-08. Phase 0 is closed, and Phase 1 can start (see [DEVELOPMENT_PLAN.md](../DEVELOPMENT_PLAN.md)).

**Checked against:** `main` at version 1.1.1, on 2026-11-08. Measurements from the original pass are in [PHASE-0-BASELINE.md](PHASE-0-BASELINE.md).

## Result

All five Phase 0 acceptance items are met. Nothing blocks Phase 1 on packaging, the vault path, or data recovery.

| Acceptance item | Result | Evidence |
| --- | --- | --- |
| Portable Windows build succeeds and app assets and fonts are present | Met | A portable build of `main` succeeded on 2026-11-08 (`VLAUTR 1.1.1.exe`, 103.8 MB). All 6 font files `page.html` uses are in `app.asar`, as are all 7 app files. No tests, docs, scripts or build output are packaged. |
| Development and packaged builds use the intended vault location, with no silent data-directory change | Met | Both builds use `%APPDATA%\my-projects\vault.json`. The packaged `package.json` still has `name: my-projects` and no `productName`, so the rename to VLAUTR did not move the vault. A packaged build was launched against the existing vault on 2026-11-03 (see the baseline). |
| Vault lifecycle, migration, corruption and interrupted-write tests pass using temporary data | Met | `npm test`: 48 of 48 pass. All tests use throwaway temporary folders. |
| Security model and known gaps are documented | Met | [SECURITY.md](SECURITY.md) covers cryptography, process boundaries, the threat model and 8 known gaps. |
| Baseline results and unresolved issues are recorded | Met | [PHASE-0-BASELINE.md](PHASE-0-BASELINE.md) records packaging, vault location, timings, test coverage and recovery behavior. |

## Work completed

| Area | Change |
| --- | --- |
| Tests | Added vault lifecycle and recovery tests (27 at the end of Phase 0). |
| Packaging | Limited `build.files` to the app's own files, so `app.asar` shrank from 6.7 MB to 4.2 MB. Stopped tracking build output in git. |
| Documentation | Added `docs/SECURITY.md`, `docs/PHASE-0-BASELINE.md`, `RULES.md` and `DEVELOPMENT_PLAN.md`. |
| Branding | Added the VL app icon and renamed the built exe to VLAUTR (`build.productName`), keeping the vault path unchanged. |

## Work done outside Phase 0

These changes landed during the Phase 0 period but belong to other phases. They are listed so the review sees the full state of `main`.

| Change | Phase | Note |
| --- | --- | --- |
| Backup codes on entries (#6, #7) | 2B | **Vault format moved to version 3, one-way.** This was done ahead of the 2A restore screens, by explicit decision. Versions 1 and 2 upgrade on unlock after a byte-for-byte backup. Older builds report a version 3 vault as corrupted. |
| Windows installer (#7) | Packaging | A per-user NSIS installer that keeps the vault on uninstall. Builds are not code-signed. |

21 of the 48 tests cover backup codes.

**Merge incident:** #6 was merged into `phase-0-stabilization` 32 seconds after #5 had merged that branch into `main`, so backup codes did not reach `main` until #7 (merged 2026-11-07). `main` is now complete, and no work was lost.

## Compatibility

- **Vault path:** unchanged throughout (`%APPDATA%\my-projects`).
- **Vault format:** version 3 since 1.1.0. Builds older than 1.1.0 cannot open an upgraded vault. To go back, restore the `vault.json.v2-*.bak` backup by hand. Anything changed after the upgrade is not in that backup.
- **App ID and package name:** unchanged (`com.mazen.passwordgenerator`, `my-projects`).

## Not verified

- **No real install or uninstall:** the installer has not been run on a real machine.
- **No real vault upgrade:** a real vault has not yet been upgraded from version 2 to 3. The upgrade was tested only on throwaway vaults, through automated tests and the running app.
- **No UI test suite:** `main.js` and `renderer.js` have no automated tests. Backup codes were checked once in the running app with a script that is not part of the repository.
- **Stale timings:** startup and unlock times were measured once, on 2026-11-03, before the rename and the installer.

## Open items carried into Phase 1

From [SECURITY.md](SECURITY.md#known-gaps-planned-for-phase-1):

1. Every decrypted password and backup code is sent to the window and kept in memory until lock.
2. Copying sends the plaintext password over IPC instead of an entry ID.
3. Saves do not `fsync` before the rename, so a power cut can leave a truncated file. That file is detected and never overwritten, but recovery is a manual restore.
4. There is no way to change the master password.
5. Backups are never pruned.
6. Nothing explicitly denies Electron permission requests.

Other open items:

- **Unsigned builds:** there is no code signing, so SmartScreen warns on first run.
- **Phase 1 plan out of date:** Phase 1's acceptance criteria in `DEVELOPMENT_PLAN.md` still refer to "v1/v2 vaults". They should now cover version 3.

## Recommended next milestone

Start Phase 1 with step 1, a threat-model and IPC review. The output should be a written design covering what the window needs to show, and which actions really need a plaintext password or backup code. This changes security boundaries, so `RULES.md` requires the owner to approve the design before implementation starts.

## Decision

Accepted by the project owner on 2026-11-08. Phase 0 is closed.

## After this report

Merged the same day as this report, after it was written:

- **#8 (version 1.1.2):** fixed vaults larger than about 4.3 MB failing to unlock. A base64 check overflowed the stack, so the vault was reported as corrupted. Vaults now open up to the documented 8 MB limit, and `npm test` runs 53 tests.
