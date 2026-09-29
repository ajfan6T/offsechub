# OffsecHub vault format, version 1

This is the normative description of how OffsecHub stores data at rest. It is precise enough to write an independent reader: see the [test vectors](#test-vectors), which have been cross-checked against independent implementations.

A vault is a directory, conventionally `<name>.ohvault`, holding one body of work. Everything in it is ciphertext, except the header, which contains no client data.

```
ACME-2026.ohvault/
├── vault.json            header: vault id, revision, keyslots, header MAC
├── vault.json.mirror     identical copy of the header (bit-rot / sync-conflict insurance)
├── db.enc                encrypted SQLite snapshot (all structured data)
├── db.enc.bak            previous good snapshot
├── db.enc.tmp            only exists mid-save
├── db.enc.corrupt-<ts>   a snapshot that failed authentication, set aside (never deleted automatically)
├── blobs/3f/3f9c…e1      encrypted evidence files, named by random 128-bit ids
└── .lock                 OS advisory lock: one app instance per vault
```

## 1. Primitives and encodings

| Purpose | Primitive | Implementation |
|---|---|---|
| Password → key | Argon2id, version 0x13, 32-byte output (RFC 9106) | `argon2-cffi` (reference C implementation) |
| Key derivation | HKDF-SHA256 (RFC 5869) | `cryptography` |
| Encryption | AES-256-GCM, 96-bit nonce, 128-bit tag | `cryptography` (OpenSSL) |
| Header MAC | HMAC-SHA256 | stdlib |
| Randomness | `os.urandom` | OS CSPRNG |

Encodings are exact:

- **Passwords** are Unicode NFC-normalised, then UTF-8 encoded. The same password typed on macOS (decomposed accents) and Windows (composed) derives the same key.
- **Canonical JSON** is `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
- **Base64** is the standard alphabet, padded.
- **`vault_id`** is 16 random bytes. It appears as 32 lowercase hex characters in JSON, and as the **raw 16 bytes** in every AAD and binary header.

| HKDF use | salt | info |
|---|---|---|
| Recovery KEK | keyslot salt (16 B) | `offsechub/v1/kek-recovery` |
| Snapshot key | per-snapshot random (32 B) | `offsechub/v1/db` |
| Header MAC key | empty | `offsechub/v1/header-mac` |
| Rollback high-water MAC key | empty | `offsechub/v1/high-water` |

## 2. Key hierarchy

```
password ─NFC/UTF-8─Argon2id(salt, m, t, p)──▶ KEK_p ─┐
recovery key (32 random bytes) ──HKDF───────▶ KEK_r ─┴─ AES-GCM unwrap ─▶ MK (32 random bytes)

MK ─HKDF(per-snapshot salt)─▶ snapshot key     (fresh key for every save)
MK ─HKDF─────────────────────▶ header MAC key
random per-blob key (32 B) ── stored only in its Evidence row inside db.enc ─▶ encrypts one blob
```

- **No key encrypts more than one stream.** Each snapshot key and each blob key is used for exactly one encryption, so AES-GCM nonce reuse is structurally impossible.
- **Per-blob keys live inside the encrypted database, not next to the blob.** Deleting an evidence row, once the old snapshots have rolled over, leaves the blob file undecryptable. This is crypto-erasure.

## 3. `vault.json`

```json
{
  "format": "offsechub-vault",
  "version": 1,
  "vault_id": "9d1c5b0e2f5a4c0b8f1e3a7d6c2b4e10",
  "revision": 7,
  "keyslots": [
    {"type": "password",
     "kdf": {"alg": "argon2id", "v": 19, "len": 32, "salt": "<b64 16B>", "m_kib": 65536, "t": 3, "p": 4},
     "nonce": "<b64 12B>", "wrapped_key": "<b64 48B>"},
    {"type": "recovery",
     "kdf": {"alg": "hkdf-sha256", "salt": "<b64 16B>"},
     "nonce": "<b64 12B>", "wrapped_key": "<b64 48B>"}
  ],
  "mac": "<hex HMAC-SHA256>"
}
```

**Keyslot wrap.**

- `wrapped_key = AES-GCM(KEK, nonce, MK, aad)`, where `aad = "offsechub-vault/v1/keyslot|" ‖ vault_id(raw) ‖ "|" ‖ type ‖ "|" ‖ canonical_json(kdf)`.
- A wrong secret shows up as a GCM tag failure. There is no separate password verifier.

**Validation happens before any KDF runs,** because the header is untrusted and Argon2 parameters control memory, time and threads before anything is authenticated. A reader must reject:

- unknown fields or algorithms
- anything other than exactly one password slot and at most one recovery slot
- a salt that isn't 16 bytes, a nonce that isn't 12, or a wrapped key that isn't 48
- Argon2 parameters outside **m 19456–4194304 KiB, t 2–10, p 1–16**, or where v ≠ 19 or len ≠ 32

**Whole-header integrity.**

- `mac = HMAC(header-MAC key, canonical_json(header without "mac"))`. Per-slot AAD can't detect a slot being *deleted*, *added* or *rolled back*; this MAC can. `revision` increases on every header write.
- The header is written atomically (temp file, fsync, rename) to both `vault.json` and `vault.json.mirror`. It is also stored inside the encrypted database as `settings["vault.header"]`.

**Reconciliation on unlock.**

1. Parse both copies and try the primary, then the mirror.
2. After MK is recovered, collect the candidates: disk copies whose MAC verifies, plus the database copy (already authenticated with the snapshot).
3. The **highest revision wins**.
4. If a disk copy fails its MAC, the user is warned. If it is older than the database copy, that's a possible rollback of a password change and the user is also warned. Either way, both files are rewritten from the winner.
5. A disk copy *newer* than the database copy is the benign case "crashed before the database was saved"; it is accepted silently.

## 4. `db.enc`: structured data

The working database is an **in-memory SQLite** database, opened with `temp_store=MEMORY` so sorts don't spill plaintext to TMPDIR, and `secure_delete=ON`. It is persisted with `Connection.serialize()` and encrypted with the same STREAM construction as blobs (§5). That means no size cap (a single AES-GCM message is limited to 2 GiB in `cryptography`) and constant memory for the cipher:

```
header (65 bytes): "OHDB" ‖ version=1 ‖ vault_id (16) ‖ generation (uint64 BE) ‖ salt (32, per snapshot) ‖ chunk_size = 65536 (uint32 BE)
chunks:            STREAM under HKDF(MK, salt, "offsechub/v1/db"), aad = header
```

**Save.** Save runs after each committed change, coalesced into one save for concurrent commits. A mutating API call returns only after its change is on disk (group commit; if the disk fails the response carries `X-OffsecHub-Saved: 0` and the UI shows the error).

1. Write `db.enc.<generation>.tmp`. The name is unique, so a save never truncates a file that might be the only copy of a recovered generation. Then fsync it.
2. Hard-link the current `db.enc` to `db.enc.bak` (link, then rename over the old `.bak`), so `db.enc` never stops existing.
3. Rename the tmp over `db.enc` and fsync the directory. Older stray tmps are then removed.

A crash at any point leaves at least one complete, authentic snapshot. The platform layer (`app/vault/durable.py`) uses `F_FULLFSYNC` on macOS and write-through renames with retry on transient sharing violations on Windows.


**When a flush fails** (disk full, drive removed), nothing is discarded. Locking still wipes the key and the plaintext database, but keeps the *sealed* (encrypted) snapshot in memory and retries the write in the background. The next unlock uses it if it is newest. On exit, an encrypted rescue copy goes to the app config directory. If the database can't even be sealed, the vault stays unlocked rather than lose data.

**Open.** This happens after taking `.lock`, so nothing is read or repaired while another instance might be saving. Order the candidates by their (unauthenticated) header generation, decrypt newest first, and stop at the first that authenticates. The next save uses a generation above every number seen, so a quarantined file's generation is never reused.

| Outcome | Meaning | Action |
|---|---|---|
| `db.enc` is newest | normal | none |
| a `db.enc.<n>.tmp` is newest | an interrupted save or rekey | use it, show a notice, and durably promote it with the first save |
| only `db.enc.bak` authenticates | `db.enc` is missing, damaged or **tampered with** (a crash can't cause this) | warn, move the bad file to `db.enc.corrupt-<ts>` (it is never rotated into `.bak`, so the good backup survives) |

**Rollback detection.**

- The local app config records a per-vault high-water mark, `{generation, HMAC(high-water key, vault_id ‖ generation)}`.
- On unlock, a lower generation raises a warning. The mark can't be forged without MK; it can only be deleted, which just disables the warning.

## 5. Blobs: evidence files

Blobs are streamed in 64 KiB chunks (STREAM construction, as in age and Tink), so RAM use is one chunk regardless of file size:

```
header:  "OHBL" ‖ version=1 ‖ blob_id (16) ‖ chunk_size = 65536 (uint32 BE)          = 25 bytes
chunk i: AES-256-GCM(blob_key, nonce_i, plaintext_i, aad = header) ‖ tag
nonce_i: 0x00 × 7 ‖ uint32 BE i ‖ last-flag (0x01 on the final chunk, else 0x00)
```

**Canonical encoding.** Writers must follow these rules and readers must enforce them:

- There is at least one chunk.
- Every non-final chunk is exactly `chunk_size` bytes.
- There is exactly one final chunk, of 0 to `chunk_size` bytes. It may be empty only if it is chunk 0 (an empty file).
- The writer buffers one chunk ahead, so a file that is an exact multiple of the chunk size ends in a *full* final chunk.
- The reader determines finality by **EOF read-ahead**, never by trying both flag values.
- `chunk_size` is checked (it must equal 65536) before it is used to size any read.
- The header binds `blob_id`, which must match the database row.

**Tampering and failures.**

- **Truncation at a chunk boundary, appended chunks, reordering, a flipped last flag, a header-only file, or a swapped blob file** all fail authentication.
- **Reads verify** the recorded size and SHA-256 at the end of the stream. A failure aborts the HTTP transfer instead of letting it end cleanly (the response carries a `Content-Length`).
- **Creation order:** write to a unique tmp file, fsync it, rename it into place, fsync the directory, and only *then* insert and commit the row.
- **Deletion order:** delete the row and commit, then delete the file only after two more saves, so neither `db.enc` nor `db.enc.bak` references it. The saver forces those saves promptly.
- **Orphans are never deleted automatically.** "Verify vault" reports missing, corrupt and orphaned files. An orphan's key lived only in its lost row, so it is undecryptable.

The **evidence fingerprint** (SHA-256 of the plaintext) is listed in reports so a client can verify delivered files independently. It is *not* a chain of custody: the operator controls both the file and the hash.

## 6. Recovery key

It's 32 random bytes plus a 2-byte checksum (`SHA-256("offsechub-recovery/v1" ‖ key)[:2]`), encoded in Crockford base32 (55 characters, padding bits zero), followed by one **mod-37 check symbol** (alphabet `0-9A-Z` minus `ILOU`, then `*~$=U`). It is displayed as `OHRK-` plus groups of five.

Decoding:

- Case-insensitive; hyphens and spaces are ignored.
- The aliases `O→0` and `I/L→1` apply.
- Because 37 is prime and larger than 32, **every single-character typo and every adjacent transposition is detected** before any cryptography runs. The UI reports a typo rather than "wrong key".

## 7. Operations and what they actually guarantee

| Operation | Effect | Guarantee |
|---|---|---|
| Create | Random MK and vault id; password and recovery slots; first snapshot written immediately; recovery key shown once. | none beyond the format |
| Unlock | Derive the KEK, unwrap MK, pick a snapshot (§4), reconcile the header (§3), take the `.lock`. Weak password-slot KDF parameters are transparently upgraded. | none beyond the format |
| Lock or auto-lock | Flush, close the in-memory database, overwrite key buffers, release the `.lock`. The idle timer counts only user input and changes, not background reads. | none beyond the format |
| Change password | New password slot and a new header revision. | The old password no longer opens *this* header. It does **not** protect data from someone who kept an old header copy and knows the old password (they hold the same MK). Use rekey for that. |
| New recovery key | Password required. Replaces the recovery slot. | Same as change password. |
| Reset password (after a recovery unlock) | New password, and the exposed recovery key is **rotated** too. | Same as change password. |
| **Rekey** | New MK; new password and recovery slots; snapshot re-encrypted; old `.bak` deleted. Crash-safe order: tmp snapshot, then header, then promote. | Old headers and old credentials decrypt nothing written from now on. Old copies still decrypt what they already contained. |
| Delete evidence or engagement | The row, including its blob key, is removed and the blob file deleted. | Unrecoverable from the live vault once `.bak` has rolled over (two saves). Old backups made before deletion still contain it. |

## 8. Known limits

See [THREAT_MODEL.md](THREAT_MODEL.md).

- **Malware running as the user while the vault is unlocked** can read process memory or drive the UI.
- **Size and timing metadata** is visible: the number and sizes of blobs, and modification times.
- **Memory hygiene.** Key buffers are `bytearray`s overwritten on lock, but CPython and OpenSSL may hold copies. Decrypted data can reach **swap** unless OS swap encryption is on (the default on macOS, and on Windows with BitLocker).
- **Plaintext exports.** Report and evidence exports you save are, by design, plaintext files outside the vault.

## Test vectors

These are in `backend/tests/test_vault_vectors.py`. Independent cross-checks: Argon2id against the reference `argon2` CLI, HKDF against `openssl kdf`, and the keyslot and snapshot decryption against PyCryptodome with a hand-written RFC 5869 HKDF.

| Vector | Input | Output |
|---|---|---|
| Argon2id KEK | `"correct horse battery staple"`, salt `"offsechub-salt16"`, m=19456 t=2 p=1 | `528bb0a98a6034439a6889c394d0678cdfd61171bdcdeff1d57a7ceac5b89659` |
| Recovery KEK | key = bytes 0..31, salt = `0x11`×16 | `6235fde4c0fabb12070d4b81693c46919a8212ac98be137a7ff0b479965ef315` |
| Recovery text | key = bytes 0..31 | `OHRK-000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FPY6R-V` |
| Keyslot wrap | KEK `8182…9085`, nonce `0x01`×12, MK = bytes 32..63, vault id `9d1c…4e10` | `f9b6d829…e6319a` (48 B) |
| Snapshot | MK above, generation 1, salt `0x22`×32, plaintext `"OffsecHub"` (one final chunk) | `4f484442 01 9d1c…4e10 0000000000000001 22…22 00010000 b2303f5141f26e8bcbab60018b1be710bf9508c2affeb7d97d` |
| Blob | key `0x44`×32, id `0x55`×16, 70 000 bytes of `i mod 251` | 70 057 bytes, SHA-256 `88ab0f44…c59acd` |
| Header MAC | header with the slot above, revision 1 | `9a74c31d844d9bf1db238bca4eb26d24862e9beb04b30b28954fb1f2dca97601` |
