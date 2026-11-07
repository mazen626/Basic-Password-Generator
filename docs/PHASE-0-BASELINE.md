# Phase 0 Baseline

Results of the Phase 0 stabilization pass (2026-11-03). Use these numbers and findings as the reference point for later phases.

**Environment:** Windows 11 Pro (build 26200), AMD Ryzen 7 9700X (16 threads), 31 GB RAM, Node.js 24.15.0, npm 12.2.0, Electron 44.2.0, electron-builder 26.15.3.

## Packaging

`npm run dist` builds successfully in about 90 seconds and produces:

| Output | Size |
| --- | --- |
| `dist/VLAUTR <version>.exe` (portable) | 103.7 MB |
| `dist/win-unpacked/resources/app.asar` | 4.2 MB |

**Fixed in Phase 0:** `build.files` was `**/*`, which packed `.claude/`, `.superdesign/`, `test/`, and other non-app files into the build. It now lists the app files explicitly. The package contains `main.js`, `preload.js`, `renderer.js`, `page.html`, `vault.js`, and `package.json`, plus the production dependencies `@fontsource/ibm-plex-sans` and `@fontsource/ibm-plex-mono`. `app.asar` shrank from 6.7 MB to 4.2 MB.

**Fonts:** all six font files `page.html` uses are inside `app.asar`. In the packaged app, IBM Plex Sans loads and is the body font.

**App icon:** a "VL" icon (`build/icon.ico`) is embedded in both executables and set as the window icon. Its source is `build/icon-source.html`; regenerate the icon files with `npm run icon`.

**Not yet configured:** code signing with a real certificate.

## Vault location

| Build | App name | Vault file |
| --- | --- | --- |
| Development (`npm start`) | `my-projects` (from `package.json` `name`) | `%APPDATA%\my-projects\vault.json` |
| Packaged (`VLAUTR <version>.exe`) | `my-projects` (the packaged `package.json` has no `productName`) | `%APPDATA%\my-projects\vault.json` |

Verified by launching the packaged build: it found the existing development vault, and no `PasswordGenerator` or `VLAUTR` folder was created in `%APPDATA%`. **Both builds share one vault.**

> **Warning:** changing `name` in `package.json`, or adding a top-level `productName`, moves the vault folder. Users would see an empty "Create vault" screen. Any rename must migrate or locate the old folder first.

`build.productName` in `package.json` only sets the executable and product names. electron-builder does not copy it into the packaged `package.json`, so it does not move the vault. It was renamed from `PasswordGenerator` to `VLAUTR` after this baseline; the measurements here were taken under the old name.

The portable build stores data in `%APPDATA%`, not next to the `.exe`. The installer build added after this baseline uses the same folder, and its uninstaller leaves that folder in place (`nsis.deleteAppDataOnUninstall` is `false`).

## Startup and unlock timings

Measured with a fresh, throwaway user-data folder, timing from process start until the unlock screen is ready.

| Build | Startup to unlock screen | Create vault | Unlock | Load entries (empty vault) |
| --- | --- | --- | --- | --- |
| `win-unpacked\PasswordGenerator.exe` (3 runs) | 155 to 234 ms | 60 to 68 ms | 59 to 63 ms | 1 ms |
| Portable `.exe` (1 run) | about 4.7 s | 57 ms | 64 ms | 1 ms |

The portable build extracts about 100 MB to a temporary folder on every launch, which accounts for most of its startup time. Unlock time is dominated by PBKDF2 (600,000 iterations).

## Automated tests

`npm test` runs 27 tests in about 1 second (Node's built-in test runner).

| File | Covers |
| --- | --- |
| `test/vault-migration.test.js` | v1 to v2 migration keeps data and backs up first; invalid legacy data leaves the file untouched |
| `test/vault-lifecycle.test.js` | Create (confirmation and length rules), wrong password, persistence across instances, no plaintext on disk, a fresh IV on every write, update and the `updatedAt` rule, delete, duplicate sites, entry validation, locked-state errors, concurrent saves, queue recovery after a failed write, backups |
| `test/vault-recovery.test.js` | Truncated, empty, non-JSON, unsupported, and oversized files; tampered ciphertext; a leftover `.tmp` file; a write that fails before the rename; restoring from a backup; the vault file disappearing while unlocked |
| `test/helpers.js` | Shared setup (temporary folders, test vault, sample entry) |

**Not covered yet:** `main.js` (IPC caller checks, idle lock, clipboard clearing, copy tokens, menu actions), `renderer.js` (generator, filters, clearing state on lock), and end-to-end UI tests.

## Recovery behavior (verified by tests)

| Situation | What happens | How to recover |
| --- | --- | --- |
| Truncated or invalid `vault.json` | The unlock screen reports a damaged file. Unlock is refused and the file is never modified. | Close the app and copy the newest `vault-backup-*.bak` or `vault.json.v*-*.bak` over `vault.json`. |
| Tampered ciphertext | Treated like a wrong password; the file is unchanged. | Same as above. |
| Leftover `vault.json.tmp` | Ignored on read, and overwritten by the next save. | Nothing to do. |
| A save fails partway | The previous `vault.json` stays intact, and later saves still work. | Nothing to do. |
| `vault.json` deleted while unlocked | Operations fail with a file-not-found error; nothing is silently recreated. Unlocking again creates a **new, empty** vault. | Restore a backup before unlocking. |

## Findings carried into Phase 1

See [SECURITY.md](SECURITY.md#known-gaps-planned-for-phase-1) for the full list. The most important are: plaintext passwords in the renderer, copy by plaintext instead of by entry ID, no `fsync` before rename, no master-password change, and backups that are never pruned.
