# OffsecHub threat model

OffsecHub holds the most sensitive thing a penetration tester produces: a client's attack map. That covers what is exposed, what is vulnerable, how it was exploited, with evidence, credentials and screenshots. This document states what OffsecHub protects, against whom, how, which test proves each control, and, just as importantly, what it does **not** protect against.

Related documents: [VAULT_FORMAT.md](VAULT_FORMAT.md) (the on-disk cryptography) and [ARCHITECTURE.md](ARCHITECTURE.md) (the process model).

## 1. System and trust boundaries

```
 ┌───────────────────────── user's machine ─────────────────────────────────────────┐
 │                                                                                    │
 │  ┌──────────── OffsecHub process (trusted while unlocked) ────────────┐           │
 │  │  webview (pywebview) ──HTTP──▶ local API ──▶ vault manager ──┐      │           │
 │  │      ▲  JS bridge (allow-listed: 2 dialogs)                  │      │           │
 │  └──────┼──────────────────────────────────────────────────────┼──────┘           │
 │         │ B1: renderer ↔ Python                  B3: process ↔ disk│                │
 │   B2: localhost TCP (127.0.0.1:<random>)                         ▼                  │
 │   other local processes, other users,        ┌─────── vault directory ────────┐   │
 │   the user's browser (web pages)             │ ciphertext only (+ header)     │   │
 │                                               └───────────────┬────────────────┘   │
 └───────────────────────────────────────────────────────────────┼────────────────────┘
                                                                  │ B4: copies leave the machine
                                              backups · cloud sync · USB · lost/stolen laptop
```

## 2. Assets

| Asset | Where it lives |
|---|---|
| Findings, scope, targets, op log, notes | the encrypted SQLite snapshot (`db.enc`); in RAM while unlocked |
| Evidence files (screenshots, pcaps, dumps) | encrypted blobs (`blobs/`); one chunk at a time in RAM when used |
| The vault password and recovery key | the user's head, a password manager, a printed recovery kit |
| The master key | RAM, only while unlocked |
| Engagement metadata (which clients, when) | inside the vault. Folder names, recent-vault paths and file timestamps are outside it (§7). |

## 3. Adversaries

| # | Adversary | Capability | In scope |
|---|---|---|---|
| A1 | Thief or finder of a laptop, disk, USB stick or backup | reads the vault directory at rest | **yes**, the primary adversary |
| A2 | Cloud-sync or backup provider, or anyone who compromises one | reads (and can modify) vault copies, including old versions | **yes** |
| A3 | Attacker with write access to the vault folder | tampers with, rolls back or swaps files | **yes**: detected, cannot forge |
| A4 | A malicious web page open in the user's browser | CSRF and DNS rebinding against localhost | **yes** |
| A5 | Another unprivileged local user, or a sandboxed app | connects to the localhost port, reads shared temp dirs | **yes** |
| A6 | A script in the app's own webview (XSS via imported scanner output) | runs JS in the app origin | **yes**: contained |
| A7 | Malware running as the same user while the vault is unlocked | reads memory, drives the UI, keylogs | **no** (§6) |
| A8 | Root or administrator, a malicious OS, a physical memory attack | anything | **no** |

## 4. Threats, controls and the tests that prove them

### At rest (A1, A2)

| Threat | Control | Proof |
|---|---|---|
| Reading client data from a copied vault | Everything is AES-256-GCM. The master key is only reachable through Argon2id (64 MiB, t=3, p=4) or a 256-bit recovery key. | `test_nothing_readable_on_disk`, `test_decoder_reads_app_written_vault` |
| Offline password guessing | Argon2id memory-hard KDF, a 12-character minimum, and a strength meter in the UI. KDF parameters are bounded, so a tampered header can't downgrade them. | `test_untrusted_kdf_parameters_are_bounded_before_use` |
| Plaintext spilling to disk during normal use | In-memory SQLite with `temp_store=MEMORY`. Uploads stream as raw request bodies into the encryptor, because multipart would spool anything over 1 MiB to a plaintext temp file. No access log. | `test_connection_pragmas_keep_plaintext_off_disk`, the upload tests |
| Deleted evidence recoverable from the live vault | Each blob's key lives only in its database row. `secure_delete=ON`. The file is removed once no retained snapshot references it. | `test_blob_deletion_waits_until_no_snapshot_references_it` |
| An old credential plus an old header copy (from sync history) | **Rekey** replaces the master key; nothing written afterwards is readable with old material. Change-password alone is honestly documented as *not* revoking old copies. | `test_rekey_revokes_old_header_and_keeps_data` |

### Integrity and availability (A3)

| Threat | Control | Proof |
|---|---|---|
| Modifying any byte of a snapshot or blob | AEAD over every chunk. Headers are associated data. Blobs are bound to their id. STREAM rules reject truncation, extension and reordering. | `test_every_snapshot_header_byte…`, `test_truncation…`, `test_appended_and_swapped…` |
| Deleting, adding or rolling back keyslots | A whole-header HMAC under a key derived from the master key, plus a revision counter. An authenticated copy lives inside the database. The newest authentic copy wins and the rest are repaired. | `test_password_change_and_header_rollback_is_repaired`, `test_tampered_or_deleted_keyslot…` |
| Rolling back the whole vault to an old snapshot | A per-machine high-water mark (a MAC under the master key) triggers a warning. | `test_snapshot_rollback_detected_by_high_water_mark` |
| A corrupted `db.enc` forcing a silent rollback and destroying the backup | Fallback to `.bak` raises a warning. The bad file is quarantined and never rotated into `.bak`. | `test_tampered_database_is_quarantined_and_backup_kept` |
| Losing or corrupting `vault.json` | A mirror copy, an in-database copy, and a **recovery kit** (the recovery slot on its own) that re-opens a vault with every header copy lost. | `test_damaged_primary_header…`, `test_recovery_kit_restores…` |
| Crashes, full disks, removed drives | A unique tmp per save, a hard-linked `.bak`, fsync with `F_FULLFSYNC` on macOS and write-through renames on Windows. A failed flush keeps the sealed snapshot and retries; on exit it leaves an encrypted rescue copy. Group commit means a 2xx is on disk. | `test_failed_flush_on_lock_keeps_the_data`, `test_recovered_tmp_survives…`, `test_interrupted_save…` |
| Two instances writing the same vault | An OS advisory lock, released automatically on crash. | `test_second_instance_cannot_open_the_same_vault` |

### The local API (A4, A5)

| Threat | Control | Proof |
|---|---|---|
| Another local process calling the API | A random port and a one-time 256-bit launch token exchanged for an `HttpOnly; SameSite=Strict` cookie holding a separate secret. The CLI uses a bearer token in `runtime.json` (0600, in a per-user directory that must be owned by the user and not group or world writable). | `test_unauthenticated_requests_are_refused`, `test_launch_token_is_single_use…` |
| DNS rebinding from a web page | An exact Host allow-list. A missing Host header or an alternate loopback spelling gets a 421. | `test_dns_rebinding_host_is_refused`, `test_host_check_fails_closed` |
| CSRF from a web page | SameSite=Strict, a required `X-Requested-With` header (forcing a preflight that is never granted), and a strict Origin check (`null` rejected). | `test_cookie_post_requires_csrf_header…`, `test_null_origin_is_refused` |
| Learning anything without authenticating | Authentication runs before routing, so unauthenticated callers get 401 only, never 404 or 423. WebSockets are refused. | `test_auth_precedes_everything_else` |
| The vault staying open because of background traffic or automation | Only UI changes and an explicit input heartbeat count as activity. Polling and CLI requests don't. | `test_only_ui_changes_and_the_heartbeat_count_as_activity` |

### Inside the app (A6)

| Threat | Control | Proof |
|---|---|---|
| Stored XSS via scanner output or evidence | React escaping; a CSP with no inline script; evidence never rendered as HTML (only raster images inline; everything else a sandboxed attachment); reports autoescaped and served with a no-script CSP; the report preview iframe fully sandboxed. | report escaping tests, `test_active_content_is_never_served_inline` |
| XSS escalating to the host through the JS bridge | pywebview dispatches dotted attribute paths without an allow-list (`fn.__globals__…`). OffsecHub **patches the dispatcher** so only two flat method names are callable (native folder dialogs), and those hold no references to the vault. | `test_desktop.py` bridge tests |
| Hostile XML in imports | `defusedxml`, which rejects entity expansion and external entities. | `test_xml_entity_expansion_is_rejected`, `test_external_entities_are_rejected` |

## 5. Security-relevant design decisions

- **The same cryptography as serious tools, no novel primitives.** Argon2id, HKDF, AES-GCM and the STREAM construction, all from maintained libraries. The format is fully specified, with known-answer vectors cross-checked against the reference Argon2 CLI, OpenSSL and PyCryptodome. An **independent decoder** (`tools/ohvault_decrypt.py`) is written from the spec alone.
- **Fail safe on the side of data.** A failed save never discards changes. A newer format version is refused ("please upgrade"), not treated as corruption. Orphaned files are reported, never auto-deleted.
- **No network.** OffsecHub makes no outbound connections. External links open in the system browser.

## 6. Out of scope, stated plainly

- **Malware as the same user while unlocked (A7).** It can read process memory, the webview's DOM, and the clipboard. Process hardening (no core dumps; on Linux, `PR_SET_DUMPABLE=0` blocks same-user ptrace and `/proc/<pid>/mem`) raises the bar but is not a boundary.
- **Memory hygiene.** Key buffers are `bytearray`s overwritten on lock, but CPython, OpenSSL and the webview may hold copies. Locking guarantees the on-disk state and the drop of the key objects, not a scrubbed heap. Decrypted pages can reach **swap or hibernation files** unless the OS encrypts them (the default on macOS; BitLocker or LUKS on Windows and Linux).
- **Rollback without a trusted counter.** The high-water mark lives on this machine. A restored old vault opened on a *different* machine can't be detected.
- **Evidence provenance to third parties.** The SHA-256 fingerprints in reports let a client check that a file is the one referenced. They don't prove *when* it was captured or that the operator didn't alter it. Signed, timestamped manifests are on the roadmap.

## 7. Plaintext that exists by design

| Artifact | Contents | Mitigation |
|---|---|---|
| Vault folder name | whatever you named it | The UI suggests neutral names. Don't name vaults after clients if folder names are sensitive. |
| `vault.json`, `vault.json.mirror` | vault id, KDF parameters, wrapped keys, MAC | no client data |
| File sizes and timestamps | the number and size of evidence files, activity times | inherent to file-per-blob storage |
| App config (`config.json`) | recent vault *paths*, per-vault high-water marks | "Remember recent vaults" can be switched off; on Windows it lives in Local, not Roaming, AppData |
| `runtime.json` | port and bearer token while running | 0600 in a per-user runtime directory; deleted on exit |
| **Exports you save** | reports (HTML, Markdown, JSON), evidence downloads, CSVs | by definition plaintext. Every export is recorded in Activity, and the UI says so. |
| `--browser` mode | the session cookie is scoped to host `127.0.0.1`, **not the port**, so another local web server the browser later visits on 127.0.0.1 would receive it; the one-time link can land in browser history | Documented as reduced-security mode with a startup warning. Use the desktop window, whose cookie jar is private and ephemeral. |

## 8. Residual risks and roadmap

- Fork detection for vaults edited on two machines through a sync folder: currently warned about, not detected.
- Signed, timestamped evidence manifests (Ed25519 plus RFC 3161).
- Locking on OS sleep and session-lock events.
- Running the unlocked vault in a short-lived child process, so locking returns memory to the OS.
- Reproducible builds, signed releases and an SBOM.
