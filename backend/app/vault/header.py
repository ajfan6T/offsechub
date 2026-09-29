"""vault.json: format marker, vault id, revision, keyslots and header MAC.

Integrity of the header as a whole
  Each keyslot is bound to its vault/type/KDF by AEAD associated data, but
  that cannot detect slots being deleted, added or rolled back. So the whole
  header carries a ``revision`` counter and an HMAC keyed from the master key.
  Copies are kept in three places:

    vault.json          primary
    vault.json.mirror   identical copy (survives bit-rot / sync conflicts)
    settings table      authenticated copy inside the encrypted database

  On unlock, :func:`reconcile` picks the newest *authentic* header and
  rewrites any copy that is missing, stale or tampered with.
"""

from __future__ import annotations

import hmac
import json
import os
import tempfile
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto
from .crypto import Argon2Params, CryptoError

FORMAT = "offsechub-vault"
VERSION = 1
HEADER_FILE = "vault.json"
MIRROR_FILE = "vault.json.mirror"
DEFAULT_ARGON2 = Argon2Params()
ARGON2_VERSION = 19  # 0x13
_SLOT_KEYS = {"type", "kdf", "nonce", "wrapped_key"}
_KDF_KEYS = {"argon2id": {"alg", "v", "len", "salt", "m_kib", "t", "p"}, "hkdf-sha256": {"alg", "salt"}}
_RECOVERY_INFO = b"offsechub/v1/kek-recovery"


class VaultFormatError(Exception):
    pass


class NewerHeaderVersion(VaultFormatError):
    """vault.json was written by a newer OffsecHub."""


def _slot_aad(vault_id: bytes, slot_type: str, kdf: dict) -> bytes:
    # vault_id enters as its 16 raw bytes (same as in db.enc).
    return b"offsechub-vault/v1/keyslot|" + vault_id + b"|" + slot_type.encode() + b"|" + crypto.canonical_json(kdf)


@dataclass
class Keyslot:
    type: str  # password | recovery
    kdf: dict
    nonce: bytes
    wrapped_key: bytes

    def to_json(self) -> dict:
        return {"type": self.type, "kdf": self.kdf, "nonce": crypto.b64e(self.nonce),
                "wrapped_key": crypto.b64e(self.wrapped_key)}

    @classmethod
    def from_json(cls, d: dict) -> "Keyslot":
        # Strict: everything here is untrusted until the MAC is checked, and the
        # KDF parameters are used *before* any authentication happens.
        try:
            if set(d) != _SLOT_KEYS:
                raise ValueError
            slot = cls(d["type"], dict(d["kdf"]), crypto.b64d(d["nonce"]), crypto.b64d(d["wrapped_key"]))
            alg = slot.kdf.get("alg")
            if slot.type not in ("password", "recovery") or alg not in _KDF_KEYS or set(slot.kdf) != _KDF_KEYS[alg]:
                raise ValueError
            if (slot.type == "password") != (alg == "argon2id"):
                raise ValueError
            if len(crypto.b64d(slot.kdf["salt"])) != 16:
                raise ValueError
            if len(slot.nonce) != crypto.NONCE_LEN or len(slot.wrapped_key) != crypto.KEY_LEN + crypto.TAG_LEN:
                raise ValueError
            if alg == "argon2id":
                if slot.kdf["v"] != ARGON2_VERSION or slot.kdf["len"] != crypto.KEY_LEN:
                    raise ValueError
                Argon2Params(int(slot.kdf["m_kib"]), int(slot.kdf["t"]), int(slot.kdf["p"])).validate()
        except (KeyError, TypeError, ValueError, CryptoError):
            raise VaultFormatError("vault header has a malformed keyslot") from None
        return slot


def _password_kek(password: str, kdf: dict) -> bytearray:
    params = Argon2Params(m_kib=int(kdf["m_kib"]), t=int(kdf["t"]), p=int(kdf["p"]))
    return crypto.derive_password_kek(password, crypto.b64d(kdf["salt"]), params)


def _recovery_kek(raw: bytes, kdf: dict) -> bytearray:
    return crypto.hkdf(raw, crypto.b64d(kdf["salt"]), _RECOVERY_INFO)


def make_password_slot(vault_id: bytes, mk: bytearray, password: str,
                       params: Argon2Params | None = None) -> Keyslot:
    params = params or DEFAULT_ARGON2
    kdf = {"alg": "argon2id", "v": ARGON2_VERSION, "len": crypto.KEY_LEN,
           "salt": crypto.b64e(crypto.random_bytes(16)), "m_kib": params.m_kib, "t": params.t, "p": params.p}
    kek = _password_kek(password, kdf)
    try:
        nonce, wrapped = crypto.wrap_key(kek, mk, _slot_aad(vault_id, "password", kdf))
    finally:
        crypto.wipe(kek)
    return Keyslot("password", kdf, nonce, wrapped)


def make_recovery_slot(vault_id: bytes, mk: bytearray) -> tuple[Keyslot, str]:
    raw = crypto.random_bytes(crypto.KEY_LEN)
    kdf = {"alg": "hkdf-sha256", "salt": crypto.b64e(crypto.random_bytes(16))}
    kek = _recovery_kek(raw, kdf)
    try:
        nonce, wrapped = crypto.wrap_key(kek, mk, _slot_aad(vault_id, "recovery", kdf))
    finally:
        crypto.wipe(kek)
    return Keyslot("recovery", kdf, nonce, wrapped), crypto.encode_recovery_key(raw)


@dataclass
class VaultHeader:
    vault_id: bytes
    revision: int = 0
    keyslots: list[Keyslot] = field(default_factory=list)
    mac: str | None = None

    @classmethod
    def new(cls) -> "VaultHeader":
        return cls(vault_id=uuid.uuid4().bytes)

    def slot(self, slot_type: str) -> Keyslot | None:
        return next((s for s in self.keyslots if s.type == slot_type), None)

    def replace_slot(self, new: Keyslot) -> None:
        self.keyslots = [s for s in self.keyslots if s.type != new.type] + [new]
        self.keyslots.sort(key=lambda s: s.type != "password")

    # ------------------------------------------------------------- unlocking

    def unlock_with_password(self, password: str) -> bytearray:
        slot = self.slot("password")
        if slot is None:
            raise CryptoError("vault has no password")
        kek = _password_kek(password, slot.kdf)
        try:
            return crypto.unwrap_key(kek, slot.nonce, slot.wrapped_key, _slot_aad(self.vault_id, "password", slot.kdf))
        finally:
            crypto.wipe(kek)

    def unlock_with_recovery(self, recovery_key: str) -> bytearray:
        slot = self.slot("recovery")
        if slot is None:
            raise CryptoError("vault has no recovery key")
        raw = crypto.decode_recovery_key(recovery_key)  # ValueError on typos, before any crypto
        kek = _recovery_kek(raw, slot.kdf)
        try:
            return crypto.unwrap_key(kek, slot.nonce, slot.wrapped_key, _slot_aad(self.vault_id, "recovery", slot.kdf))
        finally:
            crypto.wipe(kek)

    def password_slot_is_weak(self) -> bool:
        slot = self.slot("password")
        if slot is None:
            return False
        k, target = slot.kdf, DEFAULT_ARGON2
        return int(k["m_kib"]) < target.m_kib or int(k["t"]) < target.t

    # ------------------------------------------------------------- integrity

    def body(self) -> dict:
        return {"format": FORMAT, "version": VERSION, "vault_id": self.vault_id.hex(),
                "revision": self.revision, "keyslots": [s.to_json() for s in self.keyslots]}

    def sign(self, mk: bytearray) -> None:
        self.mac = crypto.header_mac(mk, crypto.canonical_json(self.body()))

    def verify(self, mk: bytearray) -> bool:
        if not self.mac:
            return False
        expected = crypto.header_mac(mk, crypto.canonical_json(self.body()))
        return hmac.compare_digest(expected, self.mac)

    def to_json(self) -> dict:
        return {**self.body(), "mac": self.mac}

    def fingerprint(self) -> str:
        return crypto.canonical_json(self.to_json()).decode()

    @classmethod
    def from_json(cls, raw) -> "VaultHeader":
        if not isinstance(raw, dict) or raw.get("format") != FORMAT:
            raise VaultFormatError("not an OffsecHub vault")
        if isinstance(raw.get("version"), int) and raw["version"] > VERSION:
            raise NewerHeaderVersion("this vault was created by a newer version of OffsecHub; please upgrade")
        if raw.get("version") != VERSION:
            raise VaultFormatError(f"unsupported vault version {raw.get('version')}")
        try:
            vault_id = bytes.fromhex(raw["vault_id"])
            revision = int(raw["revision"])
            slots = [Keyslot.from_json(s) for s in raw["keyslots"]]
            mac = raw.get("mac")
        except (KeyError, TypeError, ValueError):
            raise VaultFormatError("vault header is malformed") from None
        types = [s.type for s in slots]
        if len(vault_id) != crypto.VAULT_ID_LEN or types.count("password") != 1 or types.count("recovery") > 1 \
                or revision < 0 or (mac is not None and not isinstance(mac, str)):
            raise VaultFormatError("vault header is malformed")
        return cls(vault_id=vault_id, revision=revision, keyslots=slots, mac=mac)

    # ----------------------------------------------------------- persistence

    def save(self, directory: Path, mk: bytearray) -> None:
        """Bump the revision, sign, and atomically write primary + mirror."""
        self.revision += 1
        self.sign(mk)
        data = json.dumps(self.to_json(), indent=2).encode()
        for name in (HEADER_FILE, MIRROR_FILE):
            atomic_write(directory / name, data)
        fsync_dir(directory)


def read_header_file(path: Path) -> VaultHeader | None:
    """Parse one header copy; None if missing or unusable (a newer version raises)."""
    try:
        return VaultHeader.from_json(json.loads(path.read_text()))
    except NewerHeaderVersion:
        raise
    except (OSError, ValueError, VaultFormatError):
        return None


def load_candidates(directory: Path) -> list[VaultHeader]:
    """Header copies on disk that parse, primary first. Raises if none do."""
    found: list[VaultHeader] = []
    for name in (HEADER_FILE, MIRROR_FILE):
        h = read_header_file(directory / name)
        if h is not None and all(h.fingerprint() != x.fingerprint() for x in found):
            found.append(h)
    if not found:
        if not (directory / HEADER_FILE).exists() and not (directory / MIRROR_FILE).exists():
            raise VaultFormatError("not an OffsecHub vault (vault.json missing)")
        raise VaultFormatError("the vault header is damaged")
    ids = {h.vault_id for h in found}
    if len(ids) != 1:
        raise VaultFormatError("vault header copies disagree about the vault id")
    return found


def reconcile(disk: list[VaultHeader], db_copy: dict | None, mk: bytearray) -> tuple[VaultHeader, list[str]]:
    """Choose the authoritative header. Returns (header, warnings).

    Candidates are the on-disk copies whose MAC verifies and the copy stored in
    the (already authenticated) database. The highest revision wins: a newer
    disk copy is the benign "crashed before the database was saved" case, while
    a stale or unauthenticated disk copy means rollback or tampering.
    """
    warnings: list[str] = []
    authentic = [h for h in disk if h.verify(mk)]
    if len(authentic) < len(disk):
        warnings.append("A vault header copy failed its integrity check and was replaced "
                        "(it was modified outside OffsecHub or is damaged).")
    stored = None
    if db_copy is not None:
        try:
            stored = VaultHeader.from_json(db_copy)
        except VaultFormatError:
            stored = None
    pool = authentic + ([stored] if stored is not None else [])
    if not pool:
        raise VaultFormatError("no authentic vault header found")
    best = max(pool, key=lambda h: h.revision)
    if authentic and max(h.revision for h in authentic) < best.revision:
        warnings.append("The vault header on disk was older than the one recorded inside the vault "
                        "(possible rollback of a password change). It was restored.")
    return best, warnings


def atomic_write(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def fsync_dir(directory: Path) -> None:
    """Persist a rename. Not supported (or needed) on Windows."""
    if os.name == "nt":
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
