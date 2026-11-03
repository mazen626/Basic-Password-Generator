# VLAUTR Development Plan

## Product direction

VLAUTR is an offline-first Windows desktop password manager. Its order of priorities is security and data integrity first, useful vault capabilities second, and visual refinement alongside them. Preserve the dark-purple palette and IBM Plex typography. Core use must work without network access. Optional encrypted synchronization is a later, separately designed capability; no server may receive plaintext vault contents or the master password.

This plan is based on the project technical report and the current Phase 0 results in [`docs/PHASE-0-BASELINE.md`](docs/PHASE-0-BASELINE.md). Phase 0 has already been assigned to the coding agent and is recorded as in progress/assigned. **Do not reassign or restart Phase 0.** The baseline document records completed stabilization checks; the assigned agent should finish any remaining Phase 0 handoff items and report its result. Phase 1 is gated on that handoff being available for review.

## Current baseline and constraints

- Electron desktop app, CommonJS, HTML/CSS/JavaScript, Windows portable target; Node's built-in test runner.
- `vault.js` owns PBKDF2-HMAC-SHA256 key derivation and AES-256-GCM vault handling. Current KDF settings: 600,000 iterations and 16-byte salt; each write uses a fresh 12-byte IV.
- Vault file: `%APPDATA%\\my-projects\\vault.json` for both development and packaged builds. Renaming package/app identity can silently point users at a different data directory.
- Exact entry schema is validated. Adding fields requires a versioned migration.
- Phase 0 baseline reports `npm test`: 27 passing tests; `npm run dist` succeeds; packaged IBM Plex fonts and vault location were verified. See the baseline for recovery behaviors, timings, and current coverage gaps.
- Important known gaps: all decrypted passwords are sent to the renderer; copy IPC accepts plaintext instead of entry ID; master password change is absent; file replacement lacks fsync durability; backups are not pruned; main/renderer security paths have incomplete automated coverage.

## Phase 0 — Stabilization (already assigned; prerequisite/reference)

**Status:** Assigned to the coding agent; in progress. This plan does not create or reassign its task. The existing baseline records completed packaging, font, path, and vault-recovery verification. Agent should close out its assigned work by returning a concise completion report and flagging any unfinished acceptance items.

**Original acceptance reference:**

- Portable Windows build succeeds and app assets/fonts are present.
- Development and packaged builds use the intended existing vault location; no silent data-directory change.
- Vault lifecycle, migration, corruption, and interrupted-write tests pass using temporary data.
- Security model and known gaps are documented.
- Baseline results and unresolved issues are recorded in `docs/PHASE-0-BASELINE.md`.

**Gate to Phase 1:** review the agent's Phase 0 report against the baseline; resolve any blocking packaging, vault-path, or data-recovery issue before changing security boundaries. Phase 0 completion does not authorize broad refactoring.

## Phase 1 — Security foundation

**Goal:** reduce unnecessary plaintext exposure and make sensitive operations and file updates fail safely.

**Sequence:**

1. Threat-model and IPC review; define what the UI needs to display and which operations require plaintext.
2. Replace renderer-supplied plaintext copy with a main-process operation addressed by entry ID; validate caller, vault state, and ID.
3. Change vault read APIs so the renderer receives metadata by default and retrieves an individual password only for a user-requested reveal/copy. Clear displayed/revealed data on lock and minimize its lifetime.
4. Harden vault persistence against crash/interruption (including durable flush where supported, same-directory temporary files, serialized writes, and recovery behavior).
5. Design and implement master-password change with old-password verification, fresh salt/key derivation, encrypted rewrite, backup/recovery handling, and explicit failure rollback.
6. Add coverage for IPC sender checks, locked-state restrictions, clipboard clearing, lock-state cleanup, interrupted writes, and password-change failures.

**Acceptance criteria:**

- Renderer no longer receives every decrypted password at initial vault load; each secret transfer has a narrow user action and does not persist after lock.
- Copy requests contain an entry identifier rather than a plaintext password; arbitrary IDs, malformed payloads, wrong senders, and locked-vault calls are rejected.
- CSP, context isolation, sandboxing, and disabled Node integration remain intact; permission requests are denied unless explicitly required.
- A failed write or password change leaves either the old vault or a fully validated new vault recoverable; no silent empty-vault fallback or plaintext temp file is introduced.
- Existing v1/v2 vaults and current exact entry schema remain readable, with migration tests if format changes are necessary.
- Security-focused tests and full `npm test` pass. Security docs describe the actual improvement and remaining memory/OS limitations.

**Dependency:** Phase 0 handoff review. This phase contains security-sensitive design choices; obtain user approval of the plan before implementation.

## Phase 2 — Vault management

**Goal:** make VLAUTR a complete vault: users can recover their data safely, and the vault can hold more kinds of information without compromising compatibility. Backup and recovery comes first (2A); new record types build on it (2B).

### 2A — Backup and recovery management

**Goal:** let users inspect and restore encrypted backups safely before growing the kinds of data the vault holds.

**Sequence:** backup inventory and validation → restore preview/confirmation → automatic pre-restore backup → transactional restore → deliberate retention controls.

**Acceptance criteria:**

- UI lists eligible encrypted backups with date and size; invalid or unrelated files are not treated as vault backups.
- Restore validates the selected backup completely before touching the active vault and creates a recoverable pre-restore copy.
- Cancellation and every failure preserve the active vault. A successful restore can be unlocked and its entries verified.
- Backup retention is opt-in/configurable or conservatively bounded with clear disclosure; never delete the only known-good backup.
- Tests cover invalid, truncated, wrong-password, interrupted, canceled, and successful restore using temporary folders.
- Existing backup files remain encrypted and usable; UI follows dark-purple/IBM Plex design.

**Dependency:** Phase 1 persistence guarantees. Do not add automatic deletion until retention semantics are documented and tested.

### 2B — Vault schema and useful record types

**Goal:** extend stored information without compromising compatibility or creating opaque ad hoc fields.

Candidate features: password history, secure notes, Wi-Fi credentials, software licenses, and identity/card records. Select and scope each as a separate milestone; do not implement the entire list in one prompt.

**Acceptance criteria for each record/schema milestone:**

- A documented, versioned schema and migration plan exists before implementation.
- Migration takes an encrypted backup before rewriting, validates all records, is idempotent or safely resumable, and leaves source data intact on failure.
- Old vault fixtures open correctly after upgrade; new-format records survive lock/restart and malformed records are rejected safely.
- Sensitive fields are encrypted with the vault and excluded from logs, search indexes outside the vault, and unintended renderer state.
- UI uses explicit field labels and confirmations for destructive changes and matches existing identity.

**Dependency:** the 2A recovery workflow and approved schema design. Import/export should be a separate feature with plaintext-file warnings, explicit destination, cancellation cleanup, and no automatic upload.

## Phase 3 — Password intelligence: local password health and generator improvements

**Goal:** help users improve credentials while keeping analysis on-device.

Candidate milestones: password strength/age indicators; local weak/reused password detection; passphrase generation; ambiguous-character controls and named generator presets.

**Acceptance criteria:**

- Analysis runs locally and transmits no entries, password hashes, or usage data.
- Findings are actionable, explain their limits, and do not label an estimate as a guarantee of safety.
- Generator uses cryptographically secure randomness with unbiased selection and tests character-set guarantees and edge cases.
- Sensitive values are not exposed in logs or persistent UI state; all existing generator behavior remains covered.
- UI is usable with keyboard and screen scaling and preserves visual identity.

**Dependency:** Phase 1 renderer exposure work. Password health must not delay security fixes.

## Phase 4 — Application experience: everyday tasks and accessibility

**Goal:** make routine vault tasks clearer and faster without adding complexity for its own sake.

Candidate milestones: useful dashboard, improved search/filtering, custom categories, keyboard shortcuts, onboarding/empty states, consistent confirmation dialogs, configurable auto-lock and clipboard-clear settings, accessibility/scaling improvements.

**Acceptance criteria:**

- Each milestone addresses a documented user task and includes clear success/error/empty states.
- Security defaults remain at least as protective as current behavior; settings explain consequences and validate bounds.
- Search/filter changes do not reveal hidden secrets or leak them outside the vault process unnecessarily.
- Keyboard focus, contrast, screen scaling, and dialog ownership are checked for affected screens.
- Existing functionality and tests remain intact; no unrelated redesign or broad refactor.

**Dependency:** Phase 1 security state and Phase 2A recovery. These improvements can be scheduled independently after their prerequisites.

## Phase 5 — Multi-device: optional encrypted synchronization (future; separate approval)

**Goal:** synchronize only by explicit user choice while keeping offline operation complete and server-side plaintext impossible by design.

No implementation begins from this roadmap alone. First produce a protocol and threat-model proposal covering client-side encryption, device enrollment/revocation, key derivation and wrapping, authenticated/versioned records, conflict resolution, replay/rollback risks, metadata leakage, server trust, and recovery when a device is lost. Compare whole-vault sync with record-level sync; prefer record-level only if its added complexity is justified and reviewed.

**Acceptance criteria before build approval:**

- Written protocol, threat model, recovery story, and data-flow diagram are reviewed and approved.
- Offline CRUD, unlock, backup, and restore work with sync disabled, unavailable, or misconfigured.
- Server receives no master password, plaintext entries, or decryption key; this is tested at protocol boundaries.
- Device revocation, simultaneous edits, stale/replayed data, partial sync, and interrupted network operations have defined behavior and tests.
- Sync is opt-in, status is visible, and users can inspect/resolve conflicts without data loss.

**Dependency:** Phases 1–2, and explicit user approval of the separate design and implementation prompts.

## Phase 6 — Platform expansion (future)

Potential work: Windows Hello integration, browser extension, mobile clients, and shared protocol. Treat each platform as its own product/security milestone. Do not assume desktop Electron security boundaries transfer to a browser or mobile app.

**Acceptance criteria:** separate platform threat model; reviewed authentication and device-key lifecycle; offline behavior documented; shared vault format compatibility tests; secure update/release process; accessibility and platform-specific testing. Browser autofill must validate origins and never expose credentials to an unrelated page.

**Dependency:** stable Phase 1–2 security/data model; sync protocol approval for multi-device features.

## Prompt workflow for the coding agent

Use a separate prompt for each small milestone, following [`RULES.md`](RULES.md):

1. **Analyze only:** inspect relevant files, git status, docs, call sites, data flow, risks, and tests; make no edits.
2. **Plan:** ask for an ordered implementation plan, exact files, compatibility/migration effects, security considerations, test plan, acceptance criteria, and uncertainties. For crypto, IPC, schema, storage location, packaging identity, or sync, review and approve the design before code changes.
3. **Implement one milestone:** provide objective, existing architecture, scoped instructions, security/compatibility requirements, UI direction, explicit exclusions, acceptance criteria, and required checks. Do not bundle later phases.
4. **Verify and report:** require actual test/build results, changed-file list, compatibility effects, and unresolved risks. Review the diff before issuing the next prompt.

The reusable prompt should explicitly say whether the task is analysis-only, plan-only, or implementation; whether the agent may edit files; what data fixtures are safe; and which commands to run. Never use a real vault for tests. Do not ask the agent to begin Phase 0 again; request only its existing assigned Phase 0 status/completion report when needed.

## Progress tracking

- Phase 0: **Assigned / in progress**; baseline captured in `docs/PHASE-0-BASELINE.md`; await/review the assigned agent's handoff.
- Phase 1: **Next**, gated by Phase 0 handoff review and approval of its security design.
- Phases 2–6: **Planned**, not authorized as implementation work until reached through the prompt workflow.

Update this section only when a phase's acceptance criteria are reviewed against evidence. Record deferred criteria and risks instead of marking a phase complete by assumption.
