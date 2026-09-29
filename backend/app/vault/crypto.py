"""Vault cryptography. See docs/VAULT_FORMAT.md for the normative description.

Only standard primitives are used: Argon2id (argon2-cffi), HKDF-SHA256 and
AES-256-GCM (cryptography / OpenSSL). The one assembled construction is the
chunked blob format, which follows STREAM (nonce = counter || last-flag).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import struct
import unicodedata
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
SALT_LEN = 32
VAULT_ID_LEN = 16


class CryptoError(Exception):
    """Authentication failed or data is malformed. Deliberately unspecific."""


def random_bytes(n: int) -> bytes:
    return os.urandom(n)


def wipe(buf: bytearray | None) -> None:
    """Best-effort overwrite of key material (CPython may still hold copies)."""
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64d(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


# --------------------------------------------------------------------- KDFs


@dataclass(frozen=True)
class Argon2Params:
    m_kib: int = 65536  # 64 MiB
    t: int = 3
    p: int = 4

    # Refuse to unlock vaults whose stored parameters are absurdly weak or
    # large (a tampered header must not become a DoS or a downgrade vector).
    MIN_M_KIB = 19456  # OWASP minimum (19 MiB)
    MAX_M_KIB = 4 * 1024 * 1024  # 4 GiB
    MIN_T, MAX_T = 2, 10
    MIN_P, MAX_P = 1, 16

    def validate(self) -> None:
        # Checked *before* running Argon2: the header is untrusted, and these
        # values drive memory, time and threads ahead of any authentication.
        if not (self.MIN_M_KIB <= self.m_kib <= self.MAX_M_KIB) or not (
            self.MIN_T <= self.t <= self.MAX_T
        ) or not (self.MIN_P <= self.p <= self.MAX_P):
            raise CryptoError("unsupported key derivation parameters")


def normalize_password(password: str) -> bytes:
    """NFC so the same password typed on macOS, Windows or a Linux IME unlocks the vault."""
    return unicodedata.normalize("NFC", password).encode("utf-8")


def derive_password_kek(password: str, salt: bytes, params: Argon2Params) -> bytearray:
    params.validate()
    raw = hash_secret_raw(
        secret=normalize_password(password),
        salt=salt,
        time_cost=params.t,
        memory_cost=params.m_kib,
        parallelism=params.p,
        hash_len=KEY_LEN,
        type=Type.ID,
    )
    return bytearray(raw)


def hkdf(key: bytes | bytearray, salt: bytes, info: bytes, length: int = KEY_LEN) -> bytearray:
    return bytearray(
        HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(bytes(key))
    )


# ----------------------------------------------------------------- key wrap


def wrap_key(kek: bytes | bytearray, key: bytes | bytearray, aad: bytes) -> tuple[bytes, bytes]:
    nonce = random_bytes(NONCE_LEN)
    return nonce, AESGCM(kek).encrypt(nonce, bytes(key), aad)


def unwrap_key(kek: bytes | bytearray, nonce: bytes, wrapped: bytes, aad: bytes) -> bytearray:
    try:
        key = AESGCM(kek).decrypt(nonce, wrapped, aad)
    except InvalidTag:
        raise CryptoError("wrong password or corrupted keyslot") from None
    if len(key) != KEY_LEN:
        raise CryptoError("corrupted keyslot")
    return bytearray(key)


def header_mac(mk: bytes | bytearray, header_body: bytes) -> str:
    """HMAC over the canonical header (minus the mac field) under a key derived from MK.

    Per-slot AAD cannot detect slots being deleted, added or rolled back; this can.
    """
    key = hkdf(mk, b"", b"offsechub/v1/header-mac")
    try:
        return hmac.new(bytes(key), header_body, hashlib.sha256).hexdigest()
    finally:
        wipe(key)


# -------------------------------------------------------------- recovery key

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_CROCKFORD_DECODE = {c: i for i, c in enumerate(_CROCKFORD)}
_CROCKFORD_DECODE.update({"O": 0, "I": 1, "L": 1})
# Crockford's mod-37 check symbols. 37 is prime and > 32, so a single wrong
# character or an adjacent transposition always changes the check value.
_CHECK_ALPHABET = _CROCKFORD + "*~$=U"
RECOVERY_PREFIX = "OHRK"
_RK_BYTES = KEY_LEN + 2  # key + 16-bit hash checksum (catches multi-character errors)
_RK_CHARS = -(-_RK_BYTES * 8 // 5)


def _checksum(raw: bytes) -> bytes:
    return hashlib.sha256(b"offsechub-recovery/v1" + raw).digest()[:2]


def encode_recovery_key(raw: bytes) -> str:
    """32 random bytes + 2-byte checksum in Crockford base32, then a mod-37 check symbol."""
    if len(raw) != KEY_LEN:
        raise ValueError("recovery key must be 32 bytes")
    nbits = _RK_BYTES * 8
    value = int.from_bytes(raw + _checksum(raw), "big") << (_RK_CHARS * 5 - nbits)
    chars = "".join(_CROCKFORD[(value >> (5 * (_RK_CHARS - 1 - i))) & 31] for i in range(_RK_CHARS))
    chars += _CHECK_ALPHABET[value % 37]
    return RECOVERY_PREFIX + "-" + "-".join(chars[i : i + 5] for i in range(0, len(chars), 5))


def decode_recovery_key(text: str) -> bytes:
    """Strict decoding; raises ValueError (mentioning a typo) before any crypto runs."""
    s = text.strip().upper().replace("-", "").replace(" ", "")
    if s.startswith(RECOVERY_PREFIX):
        s = s[len(RECOVERY_PREFIX) :]
    if len(s) != _RK_CHARS + 1:
        raise ValueError("recovery key has the wrong length")
    body, check = s[:-1], s[-1]
    value = 0
    for ch in body:
        if ch not in _CROCKFORD_DECODE:
            raise ValueError("recovery key contains an invalid character")
        value = (value << 5) | _CROCKFORD_DECODE[ch]
    if check not in _CHECK_ALPHABET and check not in _CROCKFORD_DECODE:
        raise ValueError("recovery key contains an invalid character")
    check_value = _CHECK_ALPHABET.index(check) if check in _CHECK_ALPHABET else _CROCKFORD_DECODE[check]
    if value % 37 != check_value:
        raise ValueError("recovery key has a typo (check symbol mismatch)")
    pad = _RK_CHARS * 5 - _RK_BYTES * 8
    if value & ((1 << pad) - 1):
        raise ValueError("recovery key has a typo (padding bits set)")
    data = (value >> pad).to_bytes(_RK_BYTES, "big")
    raw, digest = data[:KEY_LEN], data[KEY_LEN:]
    if not hmac.compare_digest(digest, _checksum(raw)):
        raise ValueError("recovery key has a typo (checksum mismatch)")
    return raw


# ------------------------------------------------------------------ STREAM
#
# Both snapshots and blobs use the STREAM construction (as in age and Tink):
# 64 KiB chunks, nonce = 0x00*7 || uint32 counter || last-flag, the file header
# as associated data. One key per stream, so nonces never repeat under a key.

CHUNK_SIZE = 64 * 1024
MAX_CHUNKS = 2**32 - 1


def _chunk_nonce(index: int, last: bool) -> bytes:
    if index > MAX_CHUNKS:
        raise CryptoError("stream too large")
    return b"\x00" * 7 + struct.pack(">I", index) + (b"\x01" if last else b"\x00")


class StreamEncryptor:
    """Incremental encryptor. write() plaintext, then finish().

    Ciphertext is written to ``out`` as it is produced; one chunk is buffered
    (read-ahead) so the final chunk is always known and the encoding canonical.
    Tracks the plaintext SHA-256 and size.
    """

    def __init__(self, key: bytes | bytearray, header: bytes, out: BinaryIO):
        self._aead = AESGCM(key)  # accepts a bytearray: no immutable copy of the key
        self._header = header
        self._out = out
        self._buf = bytearray()
        self._index = 0
        self._sha = hashlib.sha256()
        self.size = 0
        self._done = False
        out.write(header)

    def write(self, data: bytes) -> None:
        if self._done:
            raise ValueError("encryptor already finished")
        self._sha.update(data)
        self.size += len(data)
        self._buf.extend(data)
        while len(self._buf) > CHUNK_SIZE:
            chunk = bytes(self._buf[:CHUNK_SIZE])
            del self._buf[:CHUNK_SIZE]
            self._out.write(self._aead.encrypt(_chunk_nonce(self._index, False), chunk, self._header))
            self._index += 1

    def finish(self) -> str:
        """Write the final chunk; returns the plaintext SHA-256 (hex)."""
        if not self._done:
            self._out.write(
                self._aead.encrypt(_chunk_nonce(self._index, True), bytes(self._buf), self._header)
            )
            self._buf.clear()
            self._done = True
        return self._sha.hexdigest()


def stream_decrypt(key: bytes | bytearray, header: bytes, src: BinaryIO) -> Iterator[bytes]:
    """Yield authenticated plaintext chunks following ``header``.

    Canonical encoding (enforced): at least one chunk; every non-final chunk is
    exactly CHUNK_SIZE; exactly one final chunk, detected by EOF read-ahead
    (never by trying both flag values); an empty final chunk only as chunk 0.
    An error can surface after earlier chunks were yielded, so streaming
    callers must abort the transfer rather than end it cleanly.
    """
    aead = AESGCM(key)
    enc_chunk = CHUNK_SIZE + TAG_LEN
    index = 0
    pending = src.read(enc_chunk)
    while True:
        if len(pending) < TAG_LEN:
            raise CryptoError("stream truncated")
        nxt = src.read(enc_chunk)
        last = len(nxt) == 0
        try:
            plain = aead.decrypt(_chunk_nonce(index, last), pending, header)
        except InvalidTag:
            raise CryptoError("stream failed authentication") from None
        if (not last and len(plain) != CHUNK_SIZE) or (last and index > 0 and not plain):
            raise CryptoError("stream chunk malformed")
        yield plain
        if last:
            return
        index += 1
        pending = nxt


# ------------------------------------------------------------------ snapshot

SNAPSHOT_MAGIC = b"OHDB"
SNAPSHOT_VERSION = 1
_SNAP_HEADER = struct.Struct(">4sB16sQ32sI")  # magic, version, vault_id, generation, salt, chunk_size
SNAPSHOT_HEADER_LEN = _SNAP_HEADER.size  # 65
_DB_INFO = b"offsechub/v1/db"


def write_snapshot(mk: bytes | bytearray, vault_id: bytes, generation: int, plaintext: bytes,
                   out: BinaryIO) -> None:
    """Stream-encrypt a serialized database to ``out`` (no size limit, one chunk of RAM)."""
    salt = random_bytes(SALT_LEN)
    header = _SNAP_HEADER.pack(SNAPSHOT_MAGIC, SNAPSHOT_VERSION, vault_id, generation, salt, CHUNK_SIZE)
    key = hkdf(mk, salt, _DB_INFO)
    try:
        enc = StreamEncryptor(key, header, out)
        view = memoryview(plaintext)
        for i in range(0, len(view), CHUNK_SIZE * 16):
            enc.write(view[i : i + CHUNK_SIZE * 16])
        enc.finish()
    finally:
        wipe(key)


def encrypt_snapshot(mk: bytes | bytearray, vault_id: bytes, generation: int, plaintext: bytes) -> bytes:
    import io

    buf = io.BytesIO()
    write_snapshot(mk, vault_id, generation, plaintext, buf)
    return buf.getvalue()


def peek_snapshot_generation(data: bytes) -> int:
    """Generation from the header, *unauthenticated* (only used to order attempts)."""
    if len(data) < SNAPSHOT_HEADER_LEN + TAG_LEN:
        raise CryptoError("snapshot too short")
    magic, version, _vid, generation, _salt, chunk_size = _SNAP_HEADER.unpack_from(data)
    if magic != SNAPSHOT_MAGIC or version != SNAPSHOT_VERSION or chunk_size != CHUNK_SIZE:
        raise CryptoError("not an OffsecHub snapshot")
    return generation


def decrypt_snapshot(mk: bytes | bytearray, vault_id: bytes, data: bytes) -> tuple[int, bytes]:
    import io

    peek_snapshot_generation(data)  # validates length, magic, version, chunk size
    _magic, _version, vid, generation, salt, _cs = _SNAP_HEADER.unpack_from(data)
    if not hmac.compare_digest(vid, vault_id):
        raise CryptoError("snapshot belongs to a different vault")
    header = data[:SNAPSHOT_HEADER_LEN]
    key = hkdf(mk, salt, _DB_INFO)
    try:
        src = io.BytesIO(data)
        src.seek(SNAPSHOT_HEADER_LEN)
        plaintext = b"".join(stream_decrypt(key, header, src))
    except CryptoError:
        raise CryptoError("snapshot failed authentication") from None
    finally:
        wipe(key)
    return generation, plaintext


# --------------------------------------------------------------------- blobs

BLOB_MAGIC = b"OHBL"
BLOB_VERSION = 1
_BLOB_HEADER = struct.Struct(">4sB16sI")  # magic, version, blob_id, chunk_size
BLOB_HEADER_LEN = _BLOB_HEADER.size  # 25


def new_blob_key() -> bytes:
    """A fresh random key per blob. It lives only in the encrypted database, so
    deleting the evidence row (and rekeying) cryptographically erases the file."""
    return random_bytes(KEY_LEN)


class BlobEncryptor(StreamEncryptor):
    def __init__(self, key: bytes, blob_id: bytes, out: BinaryIO):
        if len(blob_id) != VAULT_ID_LEN or len(key) != KEY_LEN:
            raise ValueError("blob id must be 16 bytes and key 32 bytes")
        super().__init__(key, _BLOB_HEADER.pack(BLOB_MAGIC, BLOB_VERSION, blob_id, CHUNK_SIZE), out)


def decrypt_blob(key: bytes, blob_id: bytes, src: BinaryIO) -> Iterator[bytes]:
    """Yield authenticated plaintext chunks of a blob. Raises CryptoError on tampering."""
    header = src.read(BLOB_HEADER_LEN)
    if len(header) != BLOB_HEADER_LEN:
        raise CryptoError("blob header truncated")
    magic, version, bid, chunk_size = _BLOB_HEADER.unpack(header)
    # chunk_size is validated before it is used to size any read.
    if magic != BLOB_MAGIC or version != BLOB_VERSION or chunk_size != CHUNK_SIZE:
        raise CryptoError("not an OffsecHub blob")
    if not hmac.compare_digest(bid, blob_id):
        raise CryptoError("blob does not match its record")
    yield from stream_decrypt(key, header, src)
