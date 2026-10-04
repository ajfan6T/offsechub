# OffsecHub architecture (local-first desktop)

OffsecHub is a **single-operator, local-first desktop application**. All engagement data (scope, targets, findings, evidence, operator logs) lives in an **encrypted vault on the tester's own disk**. There is no server, no account and no network dependency. The app never phones home.

## Why local-first

- **Data custody.** Pentest data is a client's attack map. Keeping it in an encrypted file under the tester's control is easier to defend in a client security questionnaire than any SaaS.
- **Works where testers work.** On a Kali VM, air-gapped client networks, a plane, or a client laptop with egress blocked.
- **Clear threat model.** A single user and a single process protect a single encrypted file, with no multi-tenant isolation to get wrong.
- **Differentiated.** Multi-user web platforms such as PlexTrac, Dradis, Ghostwriter and SysReptor are a crowded space. A private operator workspace is not.

## Process model

```
┌──────────────────────── OffsecHub (one process) ─────────────────────────┐
│  Desktop shell  (pywebview: WebKitGTK / WKWebView / WebView2)            │
│    • loads http://127.0.0.1:<port>/_launch?token=<one-time token>        │
│    • JS bridge: 3 functions, each a native dialog (folder, vault, save)  │
│  ───────────────────────────────────────────────────────────────────── │
│  Local API  (FastAPI + uvicorn in a background thread)                   │
│    • bound to 127.0.0.1 on an ephemeral port                             │
│    • session cookie from the one-time launch token                       │
│    • Host allow-list (anti DNS-rebinding), Origin check, CSRF header     │
│  ───────────────────────────────────────────────────────────────────── │
│  Vault manager   (app/vault/)                                            │
│    • Argon2id → KEK → unwrap master key, auto-lock timer                 │
│    • in-memory SQLite ⇄ encrypted snapshot (db.enc)                      │
│    • evidence blobs: chunked AES-256-GCM streaming                       │
│  Domain services (scope matcher, CVSS, importers, reporting)             │
└──────────────────────────────────────────────────────────────────────────┘
             │ reads/writes ciphertext only
             ▼
      ~/OffsecHub/ACME-2026.ohvault/   (see VAULT_FORMAT.md)
```

The same process can run **headless** (`offsechub --browser`) on machines without WebKit, such as minimal Kali or WSL. It then opens the system browser at the one-time launch URL. Everything else is identical.

### Shell lifecycle (`desktop.py`)

1. Harden the process (no core dumps; on Linux, not ptrace-able by the same user).
2. Refuse to start if another instance answers on the port in `runtime.json`.
3. Bind `127.0.0.1:0` ourselves (with `SO_EXCLUSIVEADDRUSE` on Windows), so the port is known before uvicorn starts. uvicorn runs in a background thread with no access log and no WebSocket support.
4. Publish `runtime.json` (port and bearer token, 0600) **only once the API answers**, so the CLI never finds a dead port.
5. Open the window at the one-time launch URL (private, ephemeral cookie jar; text selection on; the engine's own downloads off).
6. On window close, SIGINT, SIGTERM or SIGHUP: stop the server, whose shutdown flushes and locks the vault, then delete `runtime.json`. uvicorn re-raises the signals it handled once it stops, so the shell installs harmless handlers first; otherwise the default SIGTERM action would kill the process before its cleanup ran.

## Local API hardening

A localhost HTTP server can be reached by other local users, other processes and web pages the user visits (via DNS rebinding or CSRF). Each of these is handled. The full mapping from threat to control to test is in [THREAT_MODEL.md](THREAT_MODEL.md).

| Threat | Control |
|---|---|
| Another local user or process calls the API | Random ephemeral port, plus a **one-time 256-bit launch token** exchanged for an `HttpOnly; SameSite=Strict` session cookie holding a separate secret. Anything without a valid cookie or bearer token gets a 401, before routing, so nothing about vault state leaks. |
| DNS rebinding | The Host header must be **exactly** `127.0.0.1:<port>` or `localhost:<port>`. A missing Host or an alternate loopback spelling gets a 421. |
| CSRF from a page in the user's browser | SameSite=Strict, a required `X-Requested-With` header on unsafe methods, and an exact Origin match when Origin is present (`null` is refused). |
| Token leakage | The launch token is single-use; `/_launch` redirects to `/`. Access logging is off. `Referrer-Policy: no-referrer`. |
| XSS turning into host compromise | Strict CSP (`script-src 'self'`, no `eval`), React escaping, evidence never rendered as HTML, and a fully sandboxed report iframe. pywebview's bridge dispatcher walks dotted attribute paths from page script, so OffsecHub **replaces it**: no JS API object, and only three exact, allow-listed names (`pick_folder`, `pick_vault`, `save_download`), each of which opens a native dialog and checks that the calling page is OffsecHub's own. A navigation guard sends the window back to the app if anything navigates it away. |
| Downloads | The webview's own downloads are off: WKWebView re-fetches them without the session cookie, and other engines save silently. `save_download` shows a native *Save as* dialog, accepts only a same-origin `/api/…` path, fetches it with the bearer token and writes it atomically. In a browser the same links are ordinary downloads. |
| Terminal automation | `offsechub import …` reads `runtime.json` (0600, per-user runtime directory; ownership and permissions are checked). Bearer requests never reset the auto-lock timer. |
| `--browser` mode | **Reduced security, and says so at startup.** Cookies are scoped to the host, not the port, so another local web server could receive the session cookie, and the one-time link can land in browser history. The cookie name carries the port, so two instances don't overwrite each other's sessions. The browser is opened on a 0600 redirect page in the runtime directory, never with the token on its command line, where other local users could read it with `ps` and race to redeem it. The desktop window's cookie jar is private and ephemeral. |

## Concurrency and persistence

- **One in-memory SQLite connection per unlocked vault**, shared through SQLAlchemy's `StaticPool` and guarded by one `db_lock`.
  - A request's session holds the lock for the endpoint only. `get_db` is function-scoped, so the lock is released after response serialization and before the response is sent.
  - Blob I/O, Argon2 and fsync never run under `db_lock`. Uploads stream into the encryptor first, then insert their row in a short session.
- **Lock ordering:** `state_lock` → `file_lock` → `db_lock`. An endpoint that holds a DB session must never lock the vault.
- **Group commit.** Commits change memory. The saver thread coalesces them into one encrypted, atomic save. A middleware makes every mutating request wait for that save, so **a 2xx means the change is on disk**. If the disk fails, the response carries `X-OffsecHub-Saved: 0` and the UI shows a persistent "changes are not being saved" banner.
- **Lock is quiescent.**
  1. Set `closing` under `db_lock`. Requests already inside a session finish and are included in the final seal; later ones get a 423.
  2. Seal and write the snapshot under `file_lock`.
  3. Close the connection and wipe the master key under `file_lock`, so an in-flight save never encrypts with a wiped key.
  4. Join the saver thread.
- **A failed final write doesn't lose data.** The sealed ciphertext is kept in memory and retried, and on exit it is written to a rescue file. If the database can't even be sealed, the vault stays unlocked.
- **Auto-lock follows the user.** Only UI changes and an explicit input heartbeat (sent on keyboard, pointer and wheel input, throttled) reset the timer. The UI warns 60 seconds before locking. On lock it drops its query cache and returns to the unlock screen.

## Data model changes from the web edition

Everything multi-user is removed. The data model is single-operator:

- **Removed:** `User`, `AuthToken`, `EngagementMember`, global and member roles, login throttling, admin pages.
- **Added:** `Setting`, a key/value table in the encrypted DB. It holds the operator profile (`operator.name`, `operator.email`, `operator.organization`) and `vault.auto_lock_minutes`.
- **`AuditEvent`:** drops `user_id` and `ip_address`, and keeps action, entity, summary and engagement. It is renamed "Activity" in the UI.
- **`OperatorLogEntry`:** drops `user_id` and gains `operator: str`, which defaults to the profile name. This keeps it meaningful when a log is exported for SOC deconfliction.
- **`TestCase`:** drops `assignee_id`.
- **`Evidence`, `Finding`, `ReconImport`, `Engagement`:** drop their `*_by_id` user references.

## API contract

All domain endpoints keep their existing paths and payloads, minus the fields removed above. They return **423 Locked** when no vault is unlocked.

### Vault and app (new)

| Method and path | Body | Result |
|---|---|---|
| `GET /api/vault/status` | none | `{state: "none" \| "locked" \| "unlocked", path, name, auto_lock_minutes, seconds_until_lock, lock_reason, must_set_password, warnings[], notices[], dirty, last_saved_at, save_error, db_bytes}`. Does **not** reset the idle timer. |
| `POST /api/vault/create` | `{path, password}` | `{recovery_key, recovery_kit, status}`. Creates the directory `path` (must not exist or must be empty) and leaves the vault unlocked. |
| `POST /api/vault/unlock` | `{path, password}` or `{path, recovery_key[, recovery_kit]}` | `status`. The kit is needed only if every `vault.json` copy is lost. |
| `POST /api/vault/lock` | none | `status` |
| `POST /api/vault/change-password` | `{current_password, new_password}` | 204 |
| `POST /api/vault/recovery-key` | `{password}` | `{recovery_key, recovery_kit}`. Rotates the key: the old one no longer opens *this* header (only a rekey revokes old header copies). |
| `GET /api/vault/recovery-kit` | none | The current recovery slot. Contains no secret. |
| `POST /api/vault/backup` | `{path}` | `{path, generation, evidence_files, bytes}`. A consistent, verified, still-encrypted copy in a new folder. |
| `POST /api/vault/verify` | none | `{evidence, verified, missing[], corrupt[], orphaned_files}`. Nothing is deleted. |
| `GET` / `PUT /api/vault/settings` | `{auto_lock_minutes}` (0 = never, max 480) | settings |
| `GET` / `PUT /api/profile` | `{name, email, organization}` | profile |
| `GET /api/app/recent` | none | `[{path, name, exists}]`, from plaintext app config. Only paths are stored. |
| `DELETE /api/app/recent` | `{path}` (optional; omit to clear all) | 204 |
| `GET /api/app/info` | none | `{version, desktop: bool, data_dir}` |

| `POST /api/vault/close` | none | `status`. Locks and returns to the vault picker. |
| `POST /api/vault/reset-password` | `{recovery_key, new_password}` | `{recovery_key, recovery_kit}`. Only after a recovery-key unlock; it also rotates the exposed recovery key. |
| `POST /api/vault/rekey` | `{password}` | `{recovery_key, recovery_kit}`. New master key; old headers and credentials decrypt nothing new. |
| `POST /api/app/activity` | none | 204. UI heartbeat on real user input. It and unsafe methods are the only things that reset auto-lock. |
| `PUT /api/app/preferences` | `{remember_recent}` | 204 |
| `POST /api/app/recent/forget` | `{path?}` | 204 |

### Evidence and imports: raw-body streaming, no multipart

Multipart parsing spools uploads over 1 MiB to **plaintext temp files**, so these endpoints take the file as the raw request body instead. Metadata goes in the query string.

| Method and path | Body | Result |
|---|---|---|
| `POST /api/engagements/{id}/evidence/upload?filename=&description=&finding_id=&target_id=&test_case_id=` | raw file bytes; `Content-Type` = file type | `Evidence`. Streamed chunk by chunk into the encryptor (RAM ≈ one 64 KiB chunk). |
| `POST /api/engagements/{id}/imports/upload?tool=nmap\|nuclei\|list&filename=&skip_out_of_scope=true` | raw file bytes | `ReconImport`. Parsed in memory; the raw file is kept as an evidence blob. |
| `GET /api/engagements/{id}/evidence/{eid}/download[?inline=true]` | none | Streams with `Content-Length`, verifies size and SHA-256 at the end, and aborts the connection on mismatch. Inline is allowed only for raster images. |

### Removed

`/api/auth/*`, `/api/users*`, `/api/engagements/{id}/members*`, multipart uploads, and `/api/audit`, which is replaced by `GET /api/activity`, the vault-wide activity feed. Response objects no longer carry user references (`created_by`, `uploaded_by`, `assignee`, `user`, `my_role`, `ip_address`). Op-log entries carry `operator: str`.

## Repository layout

```
backend/app/
  vault/            crypto.py (primitives, STREAM, snapshot/blob formats, recovery-key encoding),
                    header.py (keyslots, header MAC/revision, reconciliation), manager.py (state machine,
                    group commit, snapshots, blob store, rekey, backup, verify), durable.py (per-OS
                    fsync/rename), fslock.py, appconfig.py (recent vaults, high-water marks,
                    runtime.json), hardening.py (no core dumps, no same-user ptrace)
  localauth.py      launch token, session cookie, Host/Origin/CSRF middleware
  desktop.py        shell: uvicorn on a pre-bound 127.0.0.1 socket, pywebview window or browser, JS bridge
  localclient.py    bearer-token client for the running app (CLI, save_download)
  cli.py            offsechub [--browser|--dev] | open | import | demo | version
  api/              domain routers (single-operator) + vault.py
  services/         scope, cvss, importers, reporting, storage (now vault-backed)
frontend/           React app; VaultGate replaces Login
packaging/          PyInstaller spec, build scripts
tools/              ohvault_decrypt.py: independent, spec-only decoder (no-lock-in escape hatch)
```

## Decisions (ADRs)

1. **pywebview over Electron or Tauri.** The trusted core is Python: the importers, crypto and reporting are already tested there. pywebview uses the OS webview (no bundled Chromium, so small binaries) and keeps the application to one language. With Tauri, the Rust shell would be a thin wrapper around a Python sidecar anyway, which adds a second trust boundary and doesn't remove the first.
2. **In-memory SQLite plus encrypted snapshots over SQLCipher.** There's no native dependency, since `cryptography` and `argon2-cffi` ship wheels for every desktop platform. The file format is simple enough to document fully and plaintext never touches disk. The costs are RAM use proportional to database size (fine for engagement data) and a coalesced save after every commit, with atomic replace and a `.bak` fallback.
3. **Per-file keys from random salts.** No nonce bookkeeping, and no key is ever reused across messages.
4. **Localhost HTTP over a pure JS bridge.** The HTTP path lets downloads, images, iframes and streaming uploads work unchanged. The bridge is used only for native dialogs. The risks of localhost HTTP are addressed explicitly (see the table above).
5. **Single operator.** Collaboration becomes **encrypted engagement export and import** (roadmap), not a shared server.
6. **Per-blob random keys stored in the database,** rather than keys derived from the master key.
   - *Gain:* deleting a row erases the file cryptographically, and a rekey needs no blob re-encryption.
   - *Cost:* an orphaned blob (its row lost in a crash before the save) can't be recovered. Group commit makes that window tiny, and "Verify vault" reports orphans.
7. **STREAM for snapshots too.**
   - *Gain:* no 2 GiB AES-GCM message cap, and a streaming cipher.
   - *Cost:* the database ceiling is set explicitly instead (1 GiB, via `max_page_count`), because RAM use is about 3× the database size while saving. A warning appears at 256 MB.
8. **Refuse, don't repair, what we don't understand.** A newer snapshot or header version is an "upgrade OffsecHub" error, never quarantine or fallback.
9. **Rebuild the bridge rather than relax the CSP.** pywebview creates its page-side API with `new Function` and returns results through `eval`, both of which `script-src 'self'` blocks. Adding `'unsafe-eval'` would have been a one-word fix that weakens the main XSS control for every page. Instead the shell injects a closure-based `_createApi` and returns results with `run_js` as JSON literals. A test runs pywebview's real `api.js` in Node with string code generation disabled to prove both halves.
