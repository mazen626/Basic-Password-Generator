# VLAUTR Coding Agent Rules

These rules apply to every change in this repository. Read them with `README.md`, `docs/SECURITY.md`, and the relevant sections of `docs/PHASE-0-BASELINE.md` before planning implementation. If an instruction conflicts with the user's current request, explain the conflict and ask before proceeding.

## Product direction

- VLAUTR is a Windows desktop password manager and generator. Keep core vault use fully functional offline.
- Treat security, confidentiality, integrity, and recoverability as higher priorities than convenience or feature count.
- Synchronization is a possible future, optional feature. Never make the vault or any core action depend on a network, account, or server. Do not implement sync without a separate approved design and prompt.
- Preserve the established dark-purple identity, IBM Plex Sans for interface text, and IBM Plex Mono for credentials and technical values. Improve the existing design in place; do not replace it wholesale.

## Scope and change discipline

- Before editing, inspect the current implementation and git status. Do not overwrite, revert, or “clean up” unrelated user changes.
- Implement only the requested milestone. Prefer the smallest coherent change; avoid broad refactors, new frameworks, and dependencies without a concrete need and explicit explanation.
- Do not change application name, `package.json` name, Electron `app.getPath('userData')` behavior, app ID, vault location, or packaging identity casually. Both development and packaged builds currently use `%APPDATA%\\my-projects\\vault.json`; a rename can make users appear to have lost their vault. Any change requires a migration/locating strategy and explicit acceptance criteria.
- Never edit generated build output as the source of truth. Keep `build.files` explicit so tests, documentation, scratch files, and development-only assets are not shipped unintentionally.
- Do not modify vault data, use a user's real vault for tests, or run migration/restore experiments against real data. Use disposable temporary directories and test fixtures.
- Do not commit, push, publish, sign, release, or contact external services unless the user explicitly requests that action.

## Security invariants

- Never write passwords, master passwords, derived keys, plaintext vault contents, recovery material, or sensitive notes to logs, telemetry, crash reports, command output, or unencrypted files.
- Never store the master password. Never weaken the current cryptographic design (PBKDF2-HMAC-SHA256, 600,000 iterations, 16-byte random salt; AES-256-GCM with a fresh 12-byte IV per write) without a reviewed, documented migration plan. Use Node/Electron cryptographic APIs and cryptographically secure randomness, not `Math.random()`.
- Keep filesystem access, encryption, key derivation, and vault authority in the Electron main process. Renderer code must not receive Node integration, direct filesystem access, raw keys, or the entire decrypted vault by default.
- Keep `contextIsolation` and renderer sandboxing enabled. Do not enable `nodeIntegration`; do not weaken the Content Security Policy, navigation restrictions, web security, or IPC sender checks to make a feature easier.
- Treat every IPC value as untrusted input. Validate types, lengths, formats, entry IDs, and operation state in the main process. Expose only narrowly scoped methods through `preload.js`; never expose generic IPC, filesystem, shell, or arbitrary invocation APIs.
- Reveal or copy only the requested credential when needed. Prefer entry-ID operations over passing plaintext credentials from the renderer. Clear sensitive UI state when locking, and retain clipboard auto-clear behavior. Do not claim JavaScript strings or process memory can be reliably zeroed; document limits honestly.
- Request no unnecessary Electron permissions. Any permission request must be explicitly handled and denied by default unless the feature has a justified, narrowly scoped need.
- Backups must remain encrypted, be validated before use, and never replace a valid vault until the candidate is fully verified. Before destructive replacement or restore, preserve a recoverable copy. Never silently discard backups; retention/pruning must be deliberate, documented, and tested.
- Errors shown to users should be useful without exposing paths, secrets, ciphertext, or implementation details. Diagnostic logs must be redacted.
- Design against the actual threat model in `docs/SECURITY.md`; do not promise protection from malware, keyloggers, or an attacker controlling the logged-in OS account unless the design supports that claim.

## Vault compatibility and data integrity

- Treat the existing encrypted vault and its exact entry schema as persistent user data. Existing vaults must remain readable through upgrades.
- The current format is versioned and v1-to-v2 migration takes a backup before rewrite. Any envelope, encryption, or entry-schema change requires an explicit versioned migration, validation, backup-before-write, failure recovery, and tests for old and new formats.
- Do not add fields to the exact validated entry shape without defining how existing entries are migrated. Preserve unknown/legacy data safely where the format permits; reject malformed input without modifying the source file.
- File writes must preserve the last known good vault across interruption and failure. Keep writes serialized. Never replace the vault with empty or partially written data on parse, authentication, validation, or I/O failure.
- Maintain documented limits (currently 10,000 entries and an 8 MB file) or change them only with tests and clear rationale.
- Preserve duplicate-site behavior and the renderer's expected error contract unless the requested feature explicitly changes it and all callers are updated.

## Architecture and code conventions

- Keep responsibilities separated: `vault.js` owns encryption, validation, and vault file operations; `main.js` owns Electron lifecycle and privileged IPC; `preload.js` owns the narrow bridge; `renderer.js` and `page.html` own presentation and user interaction.
- Keep the app dependency-light and CommonJS-compatible with the existing Electron project. Do not introduce a frontend framework or TypeScript conversion as incidental work.
- Match existing style and patterns in the file being changed. Avoid unrelated formatting churn.
- Keep user-facing copy clear and consistent. Never place secrets in HTML attributes, hidden DOM fields, URLs, local/session storage, or persistent renderer state.
- Preserve accessibility: semantic controls, keyboard operation, visible focus, readable contrast, and usable scaling. Do not communicate security state only by color.

## Verification and completion report

- For every implementation change, run the narrowest relevant checks and the existing `npm test`; run packaging checks when build configuration, assets, fonts, or distribution behavior changes. Do not claim a check passed unless it was actually run.
- Add or update tests for security boundaries, malformed input, failure paths, migration compatibility, and user-visible behavior affected by the change. Use disposable fixtures only.
- Report: objective completed; files changed; behavior and design decisions; commands/checks run with results; migration or compatibility impact; remaining risks or unverified behavior. State explicitly if a check could not be run.
- Keep `docs/SECURITY.md`, `README.md`, and the phase baseline accurate when a change alters security claims, user behavior, storage, supported platforms, or recovery instructions.

## Required prompt workflow

Work one small milestone at a time:

1. **Analyze:** inspect the request, current code, relevant docs, and git status. Identify affected files, callers, data-flow changes, compatibility risks, and unanswered assumptions. Do not edit yet.
2. **Plan:** provide a short ordered plan, security implications, migration approach if any, tests, and exact acceptance criteria. For security, crypto, IPC, vault schema, data location, packaging identity, or sync protocol changes, wait for the user's approval of the design before implementation.
3. **Implement:** change only the approved scope. Preserve user work and existing vault compatibility.
4. **Verify:** run the relevant tests/build/manual checks as specified in the prompt. Review the diff for secrets, accidental file inclusion, weakened security settings, and unrelated changes.
5. **Report:** summarize changes and verification truthfully, list unresolved risks, and recommend the next single milestone. Do not start that next milestone without a new prompt.

If the user requests a plan-only or analysis-only task, do not modify application code. If instructions or repository state are ambiguous, stop before the risky change and present the specific ambiguity and a safe recommendation.
