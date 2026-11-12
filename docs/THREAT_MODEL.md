# OffsecHub threat model

OffsecHub holds the most sensitive thing a penetration tester produces: a client's attack map. That covers what is exposed, what is vulnerable, how it was exploited, with evidence, credentials and screenshots. This document states what OffsecHub protects, against whom, how, which test proves each control, and, just as importantly, what it does **not** protect against.

Related documents: [VAULT_FORMAT.md](VAULT_FORMAT.md) (the on-disk cryptography) and [ARCHITECTURE.md](ARCHITECTURE.md) (the process model).

## 1. System and trust boundaries

```
 ┌───────────────────────── user's machine ─────────────────────────────────────────┐
 │                                                                                    │
 │  ┌──────────── OffsecHub process (trusted while unlocked) ────────────┐           │
 │  │  webview (pywebview) ──HTTP──▶ local API ──▶ vault manager ──┐      │           │
 │  │      ▲  JS bridge (allow-listed: 3 native dialogs)           │      │           │
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
| An engagement handed to a colleague | a passphrase-encrypted hand-off file (`.ohengagement`) in transit: email, chat, a shared drive, USB |
| Report templates and the report logo | inside the vault (`report_assets`), so a client's branding is protected like its data |

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
| Quitting (window close, Ctrl+C, `kill`, closing the terminal) mid-session | Every exit path stops the server, whose shutdown seals, saves and locks the vault. | `test_signals_save_lock_and_clean_up` |
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
| Stored XSS via scanner output or evidence | React escaping; a CSP with no inline script; evidence never rendered as HTML (only raster images inline; everything else a sandboxed attachment); reports autoescaped and served with a no-script CSP; the report preview iframe fully sandboxed. | report escaping tests, `test_only_raster_images_are_served_inline` |
| XSS escalating to the host through the JS bridge | pywebview dispatches dotted attribute paths without an allow-list (`fn.__globals__…`). OffsecHub passes no JS API object and **replaces the dispatcher**: only three exact names are callable, each opens a native dialog the user must confirm, each checks that the calling page is OffsecHub's own, and none holds a reference to the vault. `save_download` accepts only a same-origin `/api/` path. | `test_bridge_dispatch_refuses_everything_but_exposed_names`, `test_bridge_functions_only_serve_the_app_page`, `test_download_paths_refused` |
| Script in the page navigating the window elsewhere (phishing inside the app frame) | A navigation guard reloads the app if the window leaves its origin; external links open in the system browser. | `test_navigation_guard_returns_to_the_app` |
| Weakening the CSP to make the bridge work | pywebview needs `eval` and `new Function`. OffsecHub rebuilds both halves of the bridge without them instead of allowing `'unsafe-eval'`. | `test_page_side_api_works_without_eval` |
| Hostile XML in imports | `defusedxml`, which rejects entity expansion and external entities. Burp and Nessus put HTML in their XML: it is converted to plain text with Markdown formatting, never kept as HTML. | `test_xml_entity_expansion_is_rejected`, `test_external_entities_are_rejected`, `test_html_to_markdown_renders_the_same_text` |
| Markup injected through finding text | Finding fields take a small Markdown subset, parsed into a structure, never passed through as HTML. Links are allowed only to `http`, `https` and `mailto`; in the app they are shown, not followed. Each report format (HTML, PDF, Word, Markdown) escapes text for that format: ReportLab paragraph markup and Word XML cannot be injected, and XML-invalid control characters are removed. | `test_links_only_safe_schemes`, `test_html_never_emits_unescaped_markup`, `test_user_text_is_never_reportlab_markup`, `test_builtin_docx_report` |
| A hostile Word report template (template injection, resource exhaustion, XML attacks) | A template is a docxtpl document: Word content with Jinja tags, and it may come from anyone. It renders in Jinja's **sandbox** with autoescaping, so a tag can read the report context but cannot reach Python internals. Huge repetitions and powers are refused. On upload, and again before every render, the file is checked: at most 5 MB, a bounded zip (entry count and unpacked size), no `<!DOCTYPE` or `<!ENTITY` in any XML part, and valid template syntax. | `test_hostile_templates_are_refused`, `test_template_file_checks` |
| Spreadsheet formula injection through exported findings (CSV for Jira) | Every cell that starts with `=`, `+`, `-`, `@`, a tab or a line break is prefixed with `'`, so a spreadsheet shows it as text. Finding text often quotes what the target returned. | `test_formula_cells_are_prefixed` |

### Hand-off files (A1, A2 for files in transit; a hostile file from anyone)

A hand-off file carries one engagement, evidence included, from one vault to another ([VAULT_FORMAT.md §9](VAULT_FORMAT.md#9-hand-off-files-ohengagement)).

| Threat | Control | Proof |
|---|---|---|
| Reading an intercepted file | AES-256-GCM (STREAM) under a key derived with Argon2id from a passphrase. The app suggests a random passphrase of about 118 bits, to be sent over a different channel from the file. | `test_round_trip_into_another_vault` |
| Changing, truncating or reordering a file | Every chunk is authenticated, the header is bound in as associated data, and the last chunk is marked. Nothing is imported until the whole file has been authenticated. | `test_wrong_passphrase_tampering_and_truncation` |
| A crafted file that makes Argon2 exhaust memory or time | The KDF parameters in the header are checked against the same limits as a vault's before any key derivation. | `test_hostile_kdf_settings_are_refused_before_argon2` |
| Valid encryption around hostile contents | The manifest is validated field by field, and each evidence file must match the SHA-256 the manifest lists. On any error, the import is rolled back and the evidence written so far is deleted. | `test_invalid_contents_are_refused` |
| Overwriting work in the receiving vault | An import always creates a new engagement. If its code is taken, it gets a new one. | `test_import_into_the_same_vault_renames_the_code` |

Anyone with the passphrase can read the file. It does not identify the sender, and it carries no signature.

## 5. Security-relevant design decisions

- **The same cryptography as serious tools, no novel primitives.** Argon2id, HKDF, AES-GCM and the STREAM construction, all from maintained libraries. The format is fully specified, with known-answer vectors cross-checked against the reference Argon2 CLI, OpenSSL and PyCryptodome. An **independent decoder** (`tools/ohvault_decrypt.py`) is written from the spec alone.
- **Fail safe on the side of data.** A failed save never discards changes. A newer format version is refused ("please upgrade"), not treated as corruption. Orphaned files are reported, never auto-deleted.
- **One network request, only when you ask for it.** OffsecHub makes no outbound connections of its own, with one exception. **Settings > Check for updates** sends one HTTPS GET to `api.github.com/repos/ajfan6T/offsechub/releases/latest`. It sends no vault data and no identifier beyond what any HTTPS request carries: your IP address, and a User-Agent naming the app version. It never runs by itself, and it downloads and installs nothing. A newer version is shown as a link to the releases page. External links open in the system browser.

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
| `offsechub.log` (installed app, which has no console) | errors, warnings and vault *paths*; never vault content or secrets | in the per-user config directory; rotated at 1 MB |
| **Exports you save** | reports (PDF, Word, HTML, Markdown, JSON), findings for ticketing (CSV, SARIF, DefectDojo), evidence downloads, operator-log CSVs | by definition plaintext. Every export is recorded in Activity, and the UI says so. |
| Hand-off files | an engagement with its evidence, **encrypted** with a passphrase | protected only as well as the passphrase is chosen and kept: use the suggested one, and send it separately |
| A temporary file while a hand-off file is imported | the hand-off file as received: **still encrypted** | the system temp directory; deleted when the import ends |
| `--browser` mode | the session cookie is scoped to host `127.0.0.1`, **not the port**, so another local web server the browser later visits on 127.0.0.1 would receive it; the (already redeemed) one-time link can land in browser history | Documented as reduced-security mode with a startup warning. The link reaches the browser through a 0600 redirect page, not its command line. Use the desktop window, whose cookie jar is private and ephemeral. |

## 8. Residual risks and roadmap

- Fork detection for vaults edited on two machines through a sync folder: currently warned about, not detected.
- Signed, timestamped evidence manifests (Ed25519 plus RFC 3161).
- Locking on OS sleep and session-lock events.
- Running the unlocked vault in a short-lived child process, so locking returns memory to the OS.
- Signed hand-off files, so the receiver can tell who sent one.
- Reproducible builds and an SBOM. Signed and notarized releases are wired into CI and switch on once the signing credentials exist ([CODE_SIGNING.md](CODE_SIGNING.md)).
