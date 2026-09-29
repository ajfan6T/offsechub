#!/usr/bin/env python3
"""Independent decoder for OffsecHub vaults (docs/VAULT_FORMAT.md, version 1).

Written from the specification alone. It deliberately shares no code with
the application, so it doubles as a conformance check for the format and as
a no-lock-in escape hatch: your data stays readable without OffsecHub.

    python tools/ohvault_decrypt.py ACME.ohvault out-dir/          # prompts for the password
    python tools/ohvault_decrypt.py ACME.ohvault out-dir/ --evidence

Writes out-dir/offsechub.sqlite (and out-dir/evidence/<id>_<filename> with
--evidence). THE OUTPUT IS PLAINTEXT: put it on an encrypted disk and delete
it when done.

Requires: cryptography, argon2-cffi.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import re
import sqlite3
import struct
import sys
import unicodedata
from base64 import b64decode
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

CHUNK = 65536
TAG = 16


class FormatError(Exception):
    pass


def hkdf(key: bytes, salt: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(key)


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def stream_open(key: bytes, header: bytes, body: bytes):
    """STREAM: nonce = 0x00*7 || uint32 counter || last flag; aad = header (§5)."""
    aead, i, pos, out = AESGCM(key), 0, 0, []
    while True:
        chunk = body[pos : pos + CHUNK + TAG]
        if len(chunk) < TAG:
            raise FormatError("truncated stream")
        pos += len(chunk)
        last = pos >= len(body)
        nonce = b"\x00" * 7 + struct.pack(">I", i) + (b"\x01" if last else b"\x00")
        plain = aead.decrypt(nonce, chunk, header)
        if (not last and len(plain) != CHUNK) or (last and i > 0 and not plain):
            raise FormatError("non-canonical stream")
        out.append(plain)
        if last:
            return b"".join(out)
        i += 1


def unwrap_master_key(header: dict, password: str) -> bytes:
    """§3: Argon2id(NFC(password)) → KEK → AES-GCM unwrap with the keyslot AAD."""
    vault_id = bytes.fromhex(header["vault_id"])
    slot = next(s for s in header["keyslots"] if s["type"] == "password")
    kdf = slot["kdf"]
    if kdf["alg"] != "argon2id" or kdf["v"] != 19 or kdf["len"] != 32:
        raise FormatError("unsupported KDF")
    if not (19456 <= kdf["m_kib"] <= 4194304 and 2 <= kdf["t"] <= 10 and 1 <= kdf["p"] <= 16):
        raise FormatError("KDF parameters out of bounds")
    kek = hash_secret_raw(unicodedata.normalize("NFC", password).encode(), b64decode(kdf["salt"]),
                          time_cost=kdf["t"], memory_cost=kdf["m_kib"], parallelism=kdf["p"],
                          hash_len=32, type=Type.ID)
    aad = b"offsechub-vault/v1/keyslot|" + vault_id + b"|password|" + canonical(kdf)
    mk = AESGCM(kek).decrypt(b64decode(slot["nonce"]), b64decode(slot["wrapped_key"]), aad)
    # §3 whole-header MAC under HKDF(MK, "", "offsechub/v1/header-mac").
    body = {k: v for k, v in header.items() if k != "mac"}
    mac = hmac.new(hkdf(mk, b"", b"offsechub/v1/header-mac"), canonical(body), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(mac, header.get("mac") or ""):
        print("warning: header MAC does not verify (modified outside OffsecHub?)", file=sys.stderr)
    return mk


def open_snapshot(data: bytes, vault_id: bytes, mk: bytes) -> tuple[int, bytes]:
    """§4: 65-byte header, STREAM body under HKDF(MK, salt, "offsechub/v1/db")."""
    magic, version, vid, generation, salt, chunk = struct.unpack_from(">4sB16sQ32sI", data)
    if magic != b"OHDB" or version != 1 or chunk != CHUNK or vid != vault_id:
        raise FormatError("not a snapshot of this vault")
    return generation, stream_open(hkdf(mk, salt, b"offsechub/v1/db"), data[:65], data[65:])


def newest_snapshot(vault: Path, vault_id: bytes, mk: bytes) -> tuple[str, int, bytes]:
    names = ["db.enc", "db.enc.bak"] + [p.name for p in vault.glob("db.enc.*.tmp")]
    best = None
    for name in names:
        path = vault / name
        if not path.exists():
            continue
        try:
            gen, plain = open_snapshot(path.read_bytes(), vault_id, mk)
        except Exception as exc:  # noqa: BLE001 - report and try the next copy
            print(f"skipping {name}: {exc.__class__.__name__}", file=sys.stderr)
            continue
        if best is None or gen > best[1]:
            best = (name, gen, plain)
    if best is None:
        raise FormatError("no snapshot could be decrypted")
    return best


def open_blob(path: Path, blob_id: str, key: bytes) -> bytes:
    """§5: 25-byte header ("OHBL", version, blob id, chunk size), STREAM body."""
    data = path.read_bytes()
    magic, version, bid, chunk = struct.unpack_from(">4sB16sI", data)
    if magic != b"OHBL" or version != 1 or chunk != CHUNK or bid.hex() != blob_id:
        raise FormatError(f"blob {blob_id} header mismatch")
    return stream_open(key, data[:25], data[25:])


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("vault", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--evidence", action="store_true", help="also decrypt evidence files")
    ap.add_argument("--password", help="(insecure: visible in process lists) omit to be prompted")
    args = ap.parse_args(argv)

    header = None
    for name in ("vault.json", "vault.json.mirror"):
        try:
            header = json.loads((args.vault / name).read_text())
            break
        except (OSError, ValueError):
            continue
    if header is None or header.get("format") != "offsechub-vault" or header.get("version") != 1:
        print("not an OffsecHub v1 vault", file=sys.stderr)
        return 2
    password = args.password or getpass.getpass("Vault password: ")
    try:
        mk = unwrap_master_key(header, password)
    except Exception:  # noqa: BLE001
        print("wrong password (or damaged header)", file=sys.stderr)
        return 1
    vault_id = bytes.fromhex(header["vault_id"])
    source, generation, db = newest_snapshot(args.vault, vault_id, mk)

    args.out.mkdir(parents=True, exist_ok=True)
    db_path = args.out / "offsechub.sqlite"
    db_path.write_bytes(db)
    print(f"database: {db_path} (from {source}, generation {generation})")

    if args.evidence:
        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT storage_key, blob_key, sha256, filename FROM evidence").fetchall()
        conn.close()
        ev_dir = args.out / "evidence"
        ev_dir.mkdir(exist_ok=True)
        bad = 0
        for blob_id, key, sha, filename in rows:
            try:
                plain = open_blob(args.vault / "blobs" / blob_id[:2] / blob_id, blob_id, bytes(key))
            except Exception as exc:  # noqa: BLE001
                print(f"  ! {filename}: {exc}", file=sys.stderr)
                bad += 1
                continue
            if hashlib.sha256(plain).hexdigest() != sha:
                print(f"  ! {filename}: fingerprint mismatch", file=sys.stderr)
                bad += 1
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", filename)[:120]
            (ev_dir / f"{blob_id[:8]}_{safe}").write_bytes(plain)
        print(f"evidence: {len(rows) - bad}/{len(rows)} files verified and written to {ev_dir}")
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
