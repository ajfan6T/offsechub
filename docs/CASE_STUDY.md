# Case study: building a local-first, encrypted pentest workspace

This is the "how and why" behind OffsecHub: the product decision, the security design, and the flaws that adversarial review found in my own first draft.

## 1. The pivot: from a web platform to a private operator workspace

The first version was a conventional multi-user web app: FastAPI, React, PostgreSQL, RBAC and per-engagement teams. It worked, but it competes head-on with PlexTrac, Dradis, Ghostwriter and SysReptor, and it inherits the hardest problem in the space. A multi-tenant server that aggregates every client's attack map is a prime target.

The rewrite asks a different question: **what does a single tester need to run an engagement end to end without trusting anyone else's infrastructure?**

The answer is a desktop app whose entire state is one encrypted folder:

- It works offline, on a Kali VM, or inside a client network with no egress.
- It gives a clean data-custody story for client security questionnaires: "the data never leaves my encrypted disk, and here is the format spec".
- Its threat model fits on a page, because there's one user, one process and one file to defend.

## 2. Design principles

1. **No novel cryptography.** Argon2id, HKDF-SHA256, AES-256-GCM and the STREAM construction, all from maintained libraries (`argon2-cffi`, `cryptography`). The only thing I assembled is the file format, and it is [fully specified](VAULT_FORMAT.md).
2. **Prove it.**
   - Every security property has a named test.
   - The format has known-answer vectors, cross-checked against the reference Argon2 CLI, `openssl kdf` and PyCryptodome with a hand-written HKDF.
   - An [independent decoder](../tools/ohvault_decrypt.py), written only from the spec, decrypts real vaults in CI.
3. **Fail safe on the side of data.** A security tool that loses a week of findings is not secure in any sense that matters to its user.
4. **State limits honestly.** The [threat model](THREAT_MODEL.md) has an explicit "out of scope" section and a table of every plaintext artifact.

## 3. Architecture in one paragraph

A pywebview window (the OS's own WebKit, WebKit2 or WebView2) loads the React UI from a FastAPI server that listens on `127.0.0.1` on a random port. The server authenticates the window with a one-time launch token. The unlocked vault is an in-memory SQLite database. Each commit is sealed (serialize, then STREAM-encrypt under a fresh key) and atomically written to `db.enc`. Evidence files are streamed through the same construction, each under its own random key stored inside the encrypted database.

## 4. What adversarial review found in my own design

Before implementing, I wrote the format spec and architecture doc and ran five independent reviewers against them: applied crypto, local attack surface, durability, Python concurrency, and a "senior interviewer" lens. A skeptic then tried to refute each finding. Many survived, and several were genuinely embarrassing. Here are the most instructive.

### Correctness bugs that would have lost data

| Finding | Why it mattered | Fix |
|---|---|---|
| A failed flush on auto-lock wiped the key and closed the in-memory database anyway. | A full disk plus an idle timer meant silent loss of every unsaved change. The reviewer reproduced it. | A failed write keeps the **sealed ciphertext** in memory, since persisting it needs no key, and retries in the background. On exit it writes an encrypted rescue file. If sealing itself fails, the vault stays unlocked. |
| The recovered `db.enc.tmp` was truncated by the next save before being promoted. | One more crash lost the recovered generation. | Unique tmp names per save, a hard-linked `.bak` so `db.enc` always exists, and forced promotion of anything recovered. |
| Lock wasn't quiescent. | A request queued behind the DB lock could commit after the final seal. Separately, the saver thread could encrypt with a master key that `close()` had just zeroed, producing an undecryptable `db.enc`. | A `closing` flag set under the DB lock; key wipe under the file lock; join the saver. Covered by `test_lock_is_quiescent`. |
| A 2xx arrived before the write reached disk. | An op-log entry, the SOC deconfliction record, could vanish in a crash after being acknowledged. | **Group commit.** A function-scoped DB session releases the lock before the response is sent, and a middleware waits for the coalesced save. |
| Blob files were unlinked right after the row's deletion was committed. | A crash, or a fallback to `.bak`, left rows pointing at deleted files. | Deferred deletion: a file is removed only after two saves, when neither `db.enc` nor `.bak` references it. |
| AES-GCM in `cryptography` rejects messages over 2 GiB. | A growing vault would reach a point where it could never be saved again. | STREAM-encrypt snapshots too. An explicit, documented 1 GiB database ceiling. |
| Plain `fsync` isn't durable on macOS, and `os.replace` isn't write-through on Windows. | "Atomic and durable" was only true on Linux. | A `durable.py` layer: `F_FULLFSYNC` on macOS; `MoveFileExW(WRITE_THROUGH)` on Windows, with retry on antivirus and indexer sharing violations. |

### Security findings

| Finding | Fix |
|---|---|
| **Plaintext on disk.** Starlette spools multipart uploads over 1 MiB to temp files, and in-memory SQLite spills sorts to TMPDIR. | Raw-body streaming uploads straight into the encryptor, and `PRAGMA temp_store=MEMORY`. The false "never touches disk" wording was also replaced with a precise list of what does. |
| **pywebview's JS bridge dispatches arbitrary dotted paths** (`method.__globals__…`), so one XSS reaches the Python host. | Patch the dispatcher to an allow-list of two flat methods, and keep vault references out of the bridge. |
| **Changing the password didn't revoke old copies:** the same master key sat behind every header in sync history. | A real **rekey**. The docs now state exactly what each operation guarantees. |
| **Deleting, adding or rolling back keyslots went undetected.** | A whole-header HMAC keyed from the master key, a revision counter, and an authenticated copy inside the database. |
| **A corrupted `db.enc` forced a silent rollback** and then rotated itself over the good backup. | Quarantine the bad file, never rotate an unauthenticated file into `.bak`, and warn the user. |
| **The recovery key didn't help if `vault.json` was lost,** because its slot lived in that same file. | A **recovery kit** (the recovery slot on its own) plus the recovery key re-opens a vault with every header copy lost. |
| **Background polling and CLI automation kept the vault unlocked forever.** | Only UI changes and an explicit input heartbeat count as activity. |
| **Recovery-key typos were undetectable.** | A 16-bit checksum plus a Crockford mod-37 check symbol. 37 is prime and larger than the alphabet, so *every* single-character typo and adjacent transposition is caught, as an exhaustive test confirms. My first version had a 16-bit hash only, and its "detects every typo" test failed about 2.6% of the time. |

### What I'd tell an interviewer

- **The review paid for itself.** Most of the data-loss bugs above would only have shown up in the field: on a full disk, an unplugged USB drive, a Windows machine running Defender, or a vault that grew past 2 GiB.
- **Honest limits are a feature.** Python can't guarantee wiping memory. `--browser` mode cookies aren't port-scoped. A rollback on a different machine is undetectable. The fingerprints are integrity checks, not chain of custody. Saying so, and designing around it, is more convincing than claiming otherwise.
- **"Can someone else implement your format?"** Yes: `tools/ohvault_decrypt.py` does, in about 200 lines, and CI proves it on every commit.

## 5. Trade-offs I'd revisit with more time

- **Snapshot-per-commit vs. an encrypted append-only log.** Snapshots are simple and easy to verify. A log would make saves O(change) instead of O(database).
- **SQLCipher.** It's mature, but it adds a native dependency on every platform and gives up the fully documented, spec-reimplementable format.
- **A child process for the unlocked vault,** so locking returns memory to the OS. That gives a real guarantee in place of best-effort `bytearray` wiping.
- **Signed, timestamped evidence manifests,** to move from "integrity fingerprint" towards provenance.
