"""Vault lifecycle: create, unlock, lock, rekey, persistence and the blob store.

Concurrency
  * One in-memory SQLite connection per unlocked vault, shared through
    SQLAlchemy's StaticPool. ``OpenVault.db_lock`` serialises *all* access:
    a request's session holds it for the endpoint's duration, and the saver
    holds it only while calling ``serialize()``. One operator, so a single
    writer is never a bottleneck, and it removes every cross-request
    transaction-interleaving hazard of a shared connection.
  * A saver thread persists the database after commits (coalesced). Mutating
    requests wait for it (group commit, see app.main), so a 2xx means "on disk".
  * Blob (evidence) I/O never holds ``db_lock``.

Durability rules (docs/VAULT_FORMAT.md §4-5)
  * A save never overwrites or truncates an existing snapshot: it writes a
    uniquely named tmp, hard-links the current ``db.enc`` to ``db.enc.bak``,
    then atomically renames the tmp over ``db.enc``. ``db.enc`` always exists.
  * A failed flush never discards data: locking keeps the sealed (encrypted)
    snapshot in memory and keeps retrying the write; on exit it falls back to an
    emergency copy in the app's config directory.
  * Evidence files are deleted only once no retained snapshot references them.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import logging
import os
import re
import shutil
import sqlite3
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from . import crypto, durable
from .appconfig import AppConfig
from .crypto import CryptoError
from .fslock import DirLock, VaultInUse
from .header import (
    HEADER_FILE,
    MIRROR_FILE,
    Keyslot,
    NewerHeaderVersion,
    VaultFormatError,
    VaultHeader,
    atomic_write,
    load_candidates,
    make_password_slot,
    make_recovery_slot,
    read_header_file,
    reconcile,
)

log = logging.getLogger("offsechub.vault")

DB_FILE = "db.enc"
DB_BAK = "db.enc.bak"
BLOB_DIR = "blobs"
MIN_PASSWORD = 12
DEFAULT_AUTO_LOCK_MIN = 15
SAVE_DEBOUNCE_S = 0.05
SIZE_WARNING_BYTES = 256 * 1024 * 1024
MAX_DB_BYTES = 1024 * 1024 * 1024  # hard ceiling: bounds RAM (≈3x while saving) and save time
HEADER_SETTING = "vault.header"
KIT_FORMAT = "offsechub-recovery-kit"
_TMP_RE = re.compile(r"^db\.enc\.(\d+)\.tmp$")
_SYNC_HINTS = ("dropbox", "onedrive", "google drive", "googledrive", "icloud", "mobile documents",
               "syncthing", "nextcloud", "owncloud", "box sync")

__all__ = ["VaultManager", "OpenVault", "VaultLocked", "VaultError", "VaultInUse", "WrongSecret",
           "RecoveryInfo"]


class VaultError(Exception):
    """A user-facing vault problem (bad path, format error, weak password...)."""


class VaultLocked(Exception):
    """No vault is unlocked."""


class WrongSecret(Exception):
    """Password or recovery key did not unlock the vault."""


class BlobIntegrityError(Exception):
    """A blob decrypted but did not match its recorded size/fingerprint."""


class NewerVersion(VaultError):
    """Written by a newer OffsecHub: refuse to open, never treat as corruption."""


@dataclass(frozen=True)
class RecoveryInfo:
    """Shown to the user exactly once: the key, and a kit that restores a lost header."""

    key: str
    kit: dict


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise VaultError(f"password must be at least {MIN_PASSWORD} characters")


def make_kit(vault_id: bytes, slot: Keyslot) -> dict:
    """The recovery slot on its own. With the recovery key it re-opens a vault
    whose vault.json copies are all lost; the full header is then restored from
    the authenticated copy inside the database. Contains no secret by itself."""
    return {"format": KIT_FORMAT, "version": 1, "vault_id": vault_id.hex(), "recovery_slot": slot.to_json()}


def _new_sqlite(data: bytes | None = None) -> sqlite3.Connection:
    # check_same_thread=False is safe: db_lock guarantees one user at a time.
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    if data is not None:
        conn.deserialize(data)
    # Keep sorts/temp indices in RAM (the default spills plaintext to TMPDIR)
    # and zero deleted content so it does not linger in later snapshots.
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA foreign_keys=ON")
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    conn.execute(f"PRAGMA max_page_count={MAX_DB_BYTES // page_size}")
    return conn


def _db_header_copy(conn: sqlite3.Connection) -> dict | None:
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (HEADER_SETTING,)).fetchone()
    except sqlite3.OperationalError:  # brand-new vault: no tables yet
        return None
    if row is None or row[0] is None:
        return None
    value = json.loads(row[0]) if isinstance(row[0], str) else row[0]
    return value if isinstance(value, dict) else None


def _header_copies_match(path: Path, header: VaultHeader) -> bool:
    want = header.fingerprint()
    for name in (HEADER_FILE, MIRROR_FILE):
        h = read_header_file(path / name)
        if h is None or h.fingerprint() != want:
            return False
    return True


def _location_notices(path: Path) -> list[str]:
    lowered = str(path).lower()
    notices = []
    if any(hint in lowered for hint in _SYNC_HINTS):
        notices.append(
            "This vault is inside a cloud-sync folder. That is fine as a backup target, but never "
            "open it on two computers at once: edits made on both sides cannot be merged."
        )
    if any("conflict" in p.name.lower() for p in path.iterdir()):
        notices.append("Sync-conflict copies were found in the vault folder; OffsecHub ignores them.")
    return notices


@dataclass
class Sealed:
    """An encrypted snapshot waiting to be written (needs no key to persist)."""

    generation: int
    ciphertext: bytes


@dataclass
class _Candidate:
    source: str
    path: Path
    generation: int  # from the unauthenticated header; only orders attempts


# ================================================================ open vault


class OpenVault:
    """An unlocked vault. Holds the master key; everything goes through here."""

    def __init__(self, path: Path, header: VaultHeader, mk: bytearray, conn: sqlite3.Connection,
                 generation: int, dirlock: DirLock, unlocked_via: str, persisted: bool = True):
        self.path = path
        self.header = header
        self._mk = mk
        self._conn = conn
        self.generation = generation
        self._dirlock = dirlock
        self.unlocked_via = unlocked_via  # password | recovery | create
        self.warnings: list[str] = []
        self.notices: list[str] = []
        self.db_lock = threading.Lock()
        self.closed = False
        self.closing = False  # set under db_lock: no new sessions once the final seal starts
        self.last_save_error: str | None = None
        self.last_saved_at: datetime | None = None
        self.last_db_bytes: int | None = None
        self.db_enc_trusted = persisted  # db.enc authenticated at unlock or written by us
        self._commit_seq = 0
        self._saved_seq = 0 if persisted else -1  # a new vault's first save is forced
        self._saved_marker = self._change_marker()
        self._force_save = False
        self._pending_deletes: list[tuple[str, int]] = []
        self._save_cv = threading.Condition()
        self._saver_stop = False
        self._file_lock = threading.RLock()  # serialises snapshot/header writes and blob sweeps

        self.engine: Engine = create_engine("sqlite://", creator=lambda: conn, poolclass=StaticPool)
        self.Session = sessionmaker(bind=self.engine, autoflush=False, expire_on_commit=False)
        event.listen(self.Session, "after_commit", lambda _s: self._mark_dirty())

        self._saver = threading.Thread(target=self._saver_loop, name="vault-saver", daemon=True)
        self._saver.start()

    # ------------------------------------------------------------- identity

    @property
    def name(self) -> str:
        return self.path.name.removesuffix(".ohvault")

    @property
    def vault_id(self) -> bytes:
        return self.header.vault_id

    @property
    def commit_seq(self) -> int:
        return self._commit_seq

    @property
    def must_set_password(self) -> bool:
        return self.unlocked_via == "recovery"

    def _change_marker(self) -> tuple[int, int]:
        # Catches writes that bypass the ORM hook (raw SQL, DDL).
        return self._conn.total_changes, self._conn.execute("PRAGMA schema_version").fetchone()[0]

    @property
    def dirty(self) -> bool:
        return self._force_save or self._commit_seq != self._saved_seq


    # ----------------------------------------------------------------- DB

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Exclusive DB session. Raises VaultLocked if the vault closed meanwhile."""
        self.db_lock.acquire()
        try:
            if self.closed or self.closing:
                raise VaultLocked()
            s = self.Session()
            try:
                yield s
            finally:
                s.close()
        finally:
            self.db_lock.release()

    def _mark_dirty(self, *, force: bool = False) -> None:
        with self._save_cv:
            self._commit_seq += 1
            if force:
                self._force_save = True
            self._save_cv.notify_all()

    def wait_saved(self, seq: int, timeout: float) -> bool:
        """Block until changes up to ``seq`` are on disk (group commit)."""
        deadline = time.monotonic() + timeout
        with self._save_cv:
            while self._saved_seq < seq and not self.closed:
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                self._save_cv.wait(left)
            return self._saved_seq >= seq

    def _saver_loop(self) -> None:
        while True:
            with self._save_cv:
                while not self._saver_stop and not self.dirty:
                    self._save_cv.wait()
                if self._saver_stop:
                    return
            time.sleep(SAVE_DEBOUNCE_S)  # coalesce bursts of commits
            try:
                self.save()
            except Exception as exc:  # disk full, permissions, removed drive...
                log.exception("vault save failed")
                self.last_save_error = f"Changes are safe in memory but could not be written to disk: {exc}"
                with self._save_cv:
                    self._save_cv.notify_all()
                time.sleep(2)

    def _seal(self) -> tuple[Sealed, int]:
        """Serialize and encrypt the current database. Returns (sealed, commit_seq)."""
        with self.db_lock:
            if self.closed:
                raise VaultLocked()
            if self._conn.in_transaction:
                raise RuntimeError("refusing to serialize with an open transaction")
            seq = self._commit_seq
            marker = self._change_marker()
            data = self._conn.serialize()
        self.last_db_bytes = len(data)
        generation = self.generation + 1
        sealed = Sealed(generation, crypto.encrypt_snapshot(self._mk, self.vault_id, generation, data))
        self._saved_marker = marker
        return sealed, seq

    def save(self) -> None:
        """Persist the database now (no-op if nothing changed)."""
        with self._file_lock:
            if self.closed or (self._saver_stop and threading.current_thread() is self._saver):
                return
            with self.db_lock:
                if not self.dirty and self._change_marker() == self._saved_marker:
                    return
            self._force_save = False
            sealed, seq = self._seal()
            self._write_sealed(sealed)
            self._after_save(sealed.generation, seq)

    def _after_save(self, generation: int, seq: int) -> None:
        self.generation = generation
        self.last_saved_at = datetime.now(timezone.utc)
        self.last_save_error = None
        with self._save_cv:
            self._saved_seq = max(self._saved_seq, seq)
            self._save_cv.notify_all()
        self._sweep_blobs()

    def _write_sealed(self, sealed: Sealed) -> None:
        write_snapshot_file(self.path, sealed, rotate_bak=self.db_enc_trusted)
        self.db_enc_trusted = True

    def _store_header_copy(self) -> None:
        """Keep an authenticated copy of the header inside the database."""
        with self.db_lock:
            self._conn.execute(
                "INSERT INTO settings(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (HEADER_SETTING, json.dumps(self.header.to_json())),
            )
            self._conn.commit()
        self._mark_dirty()

    # ---------------------------------------------------------------- blobs

    def _blob_path(self, blob_id: str) -> Path:
        if len(blob_id) != 32 or any(c not in "0123456789abcdef" for c in blob_id):
            raise ValueError("invalid blob id")
        return self.path / BLOB_DIR / blob_id[:2] / blob_id

    def write_blob(self, chunks: Iterator[bytes] | BinaryIO | bytes,
                   limit: int | None = None) -> tuple[str, bytes, str, int]:
        """Encrypt a stream into a new blob with its own random key.

        Returns (blob_id, blob_key, sha256_hex, size). The key must be stored
        in the database row that references the blob. Raises ValueError if
        ``limit`` bytes are exceeded (nothing is left behind).
        """
        if isinstance(chunks, (bytes, bytearray)):
            chunks = iter([bytes(chunks)])
        elif hasattr(chunks, "read"):
            src = chunks
            chunks = iter(lambda: src.read(crypto.CHUNK_SIZE), b"")
        writer = self.open_blob_writer(limit)
        try:
            for part in chunks:
                writer.write(part)
            return writer.commit()
        finally:
            writer.abort()

    def open_blob_writer(self, limit: int | None = None) -> "BlobWriter":
        """Incremental writer for async callers (e.g. streaming an HTTP body).

        Does not hold db_lock. Call ``commit()`` to finish or ``abort()`` on error.
        """
        return BlobWriter(self, limit)

    def read_blob(self, blob_id: str, key: bytes, *, sha256: str | None = None,
                  size: int | None = None) -> Iterator[bytes]:
        """Stream a blob's plaintext. Verifies size and fingerprint at the end.

        On any failure the iterator raises, which aborts an HTTP transfer
        instead of letting it end as if complete.
        """
        path = self._blob_path(blob_id)
        if not path.exists():
            raise FileNotFoundError(blob_id)

        def gen():
            digest, total = hashlib.sha256(), 0
            with open(path, "rb") as fh:
                for chunk in crypto.decrypt_blob(key, bytes.fromhex(blob_id), fh):
                    digest.update(chunk)
                    total += len(chunk)
                    yield chunk
            if (size is not None and total != size) or (
                sha256 is not None and not hmac.compare_digest(digest.hexdigest(), sha256)
            ):
                raise BlobIntegrityError(f"evidence {blob_id} does not match its fingerprint")

        return gen()

    def read_blob_bytes(self, blob_id: str, key: bytes, **kw) -> bytes:
        return b"".join(self.read_blob(blob_id, key, **kw))

    def delete_blob(self, blob_id: str) -> None:
        """Schedule a blob file for deletion once no retained snapshot references it.

        Call after the referencing row's deletion is committed. The file is
        removed after two more saves (so neither db.enc nor db.enc.bak points
        at it); the saver forces those saves promptly. Never needs db_lock.
        """
        self._blob_path(blob_id)  # validate
        with self._save_cv:
            self._pending_deletes.append((blob_id, self.generation + 2))
            self._force_save = True
            self._save_cv.notify_all()

    def _sweep_blobs(self) -> None:
        with self._file_lock:
            due = [b for b, g in self._pending_deletes if g <= self.generation]
            self._pending_deletes = [(b, g) for b, g in self._pending_deletes if g > self.generation]
            for blob_id in due:
                try:
                    durable.unlink(self._blob_path(blob_id))
                except OSError:
                    log.warning("could not remove blob %s", blob_id)
            if self._pending_deletes:
                with self._save_cv:
                    self._force_save = True
                    self._save_cv.notify_all()

    def blob_ids_on_disk(self) -> set[str]:
        root = self.path / BLOB_DIR
        if not root.exists():
            return set()
        return {p.name for p in root.glob("*/*") if p.is_file() and not p.name.startswith(".")}

    def verify(self) -> dict:
        """Authenticate every referenced blob and report missing/orphaned/corrupt files.

        Nothing is deleted: an orphan may still be referenced by another copy of
        the vault (a backup, or the other side of a sync conflict).
        """
        with self.db_lock:
            rows = self._conn.execute("SELECT storage_key, blob_key, sha256, size, filename FROM evidence").fetchall()
        on_disk = self.blob_ids_on_disk()
        pending = {b for b, _ in self._pending_deletes}
        missing, corrupt = [], []
        for blob_id, key, sha, size, filename in rows:
            if blob_id not in on_disk:
                missing.append(filename)
                continue
            try:
                for _ in self.read_blob(blob_id, bytes(key), sha256=sha, size=size):
                    pass
            except (CryptoError, BlobIntegrityError):
                corrupt.append(filename)
        referenced = {r[0] for r in rows}
        orphaned = sorted(on_disk - referenced - pending)
        return {"evidence": len(rows), "verified": len(rows) - len(missing) - len(corrupt),
                "missing": missing, "corrupt": corrupt, "orphaned_files": len(orphaned)}

    # --------------------------------------------------------------- backup

    def export_backup(self, dest: Path) -> dict:
        """Write a consistent, verified copy of the vault to a new directory.

        The copy is a normal vault (same password). Holding the file lock
        pauses saves and blob sweeps, so the copied snapshot and blobs agree.
        """
        dest = Path(dest).expanduser()
        if dest.suffix != ".ohvault":
            dest = dest.with_name(dest.name + ".ohvault")
        if dest.exists() and any(dest.iterdir()):
            raise VaultError(f"{dest} already exists and is not empty")
        self.save()
        with self._file_lock:
            dest.mkdir(parents=True, exist_ok=True)
            for name in (HEADER_FILE, MIRROR_FILE, DB_FILE):
                shutil.copyfile(self.path / name, dest / name)
            copied = 0
            for blob_id in self.blob_ids_on_disk():
                src = self._blob_path(blob_id)
                target = dest / BLOB_DIR / blob_id[:2] / blob_id
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, target)
                copied += 1
        # Verify the copy decrypts and that every referenced blob is present.
        gen, data = crypto.decrypt_snapshot(self._mk, self.vault_id, (dest / DB_FILE).read_bytes())
        conn = _new_sqlite(data)
        try:
            keys = {r[0] for r in conn.execute("SELECT storage_key FROM evidence")}
        finally:
            conn.close()
        present = {p.name for p in (dest / BLOB_DIR).glob("*/*")} if (dest / BLOB_DIR).exists() else set()
        if keys - present:
            raise VaultError("backup verification failed: evidence files are missing from the copy")
        size = sum(p.stat().st_size for p in dest.rglob("*") if p.is_file())
        return {"path": str(dest), "generation": gen, "evidence_files": copied, "bytes": size}

    # ------------------------------------------------------------- secrets

    def _check_password(self, password: str) -> None:
        try:
            crypto.wipe(self.header.unlock_with_password(password))
        except CryptoError:
            raise WrongSecret("password is incorrect") from None

    def _check_recovery(self, recovery_key: str) -> None:
        try:
            crypto.wipe(self.header.unlock_with_recovery(recovery_key))
        except CryptoError:
            raise WrongSecret("recovery key is incorrect") from None
        except ValueError as exc:
            raise WrongSecret(str(exc)) from None

    def _save_header(self) -> None:
        with self._file_lock:
            self.header.save(self.path, self._mk)
        self._store_header_copy()

    def recovery_kit(self) -> dict:
        return make_kit(self.vault_id, self.header.slot("recovery"))

    def change_password(self, current: str, new: str) -> None:
        validate_password(new)
        self._check_password(current)
        self.header.replace_slot(make_password_slot(self.vault_id, self._mk, new))
        self._save_header()

    def reset_password(self, recovery_key: str, new: str) -> RecoveryInfo:
        """After a recovery unlock: set a new password and rotate the (now exposed) recovery key."""
        validate_password(new)
        self._check_recovery(recovery_key)
        self.header.replace_slot(make_password_slot(self.vault_id, self._mk, new))
        slot, text = make_recovery_slot(self.vault_id, self._mk)
        self.header.replace_slot(slot)
        self._save_header()
        self.unlocked_via = "password"
        return RecoveryInfo(text, make_kit(self.vault_id, slot))

    def rotate_recovery_key(self, password: str) -> RecoveryInfo:
        self._check_password(password)
        slot, text = make_recovery_slot(self.vault_id, self._mk)
        self.header.replace_slot(slot)
        self._save_header()
        return RecoveryInfo(text, make_kit(self.vault_id, slot))

    def rekey(self, password: str) -> RecoveryInfo:
        """Replace the master key (after a suspected compromise).

        Old headers and old credentials stop decrypting anything written from
        now on. Crash-safe ordering: the snapshot under the new key goes to a
        tmp file first, then the header, then the tmp is promoted; an
        interrupted rekey is recovered by the newest-authentic-snapshot rule.
        Blob keys live in the database, so blobs need no re-encryption.
        """
        self._check_password(password)
        with self._file_lock:
            self.save()
            new_mk = bytearray(crypto.random_bytes(crypto.KEY_LEN))
            new_header = VaultHeader(vault_id=self.vault_id, revision=self.header.revision + 1)
            new_header.replace_slot(make_password_slot(self.vault_id, new_mk, password))
            slot, text = make_recovery_slot(self.vault_id, new_mk)
            new_header.replace_slot(slot)
            new_header.sign(new_mk)
            with self.db_lock:
                self._conn.execute(
                    "INSERT INTO settings(key, value) VALUES(?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (HEADER_SETTING, json.dumps(new_header.to_json())),
                )
                self._conn.commit()
                seq = self._commit_seq
                data = self._conn.serialize()
                self._saved_marker = self._change_marker()
            generation = self.generation + 1
            tmp = self.path / f"db.enc.{generation}.tmp"
            with open(tmp, "wb") as fh:
                crypto.write_snapshot(new_mk, self.vault_id, generation, data, fh)
                durable.fsync_file(fh)
            body = json.dumps(new_header.to_json(), indent=2).encode()
            for name in (HEADER_FILE, MIRROR_FILE):
                atomic_write(self.path / name, body)
            durable.replace(tmp, self.path / DB_FILE)
            durable.unlink(self.path / DB_BAK)  # encrypted under the old key
            durable.fsync_dir(self.path)
            old, self._mk = self._mk, new_mk
            crypto.wipe(old)
            self.header = new_header
            self._after_save(generation, seq)
        return RecoveryInfo(text, make_kit(self.vault_id, slot))

    def high_water_mac(self, generation: int) -> str:
        key = crypto.hkdf(self._mk, b"", b"offsechub/v1/high-water")
        try:
            msg = self.vault_id + generation.to_bytes(8, "big")
            return hmac.new(bytes(key), msg, hashlib.sha256).hexdigest()
        finally:
            crypto.wipe(key)

    # ---------------------------------------------------------------- close

    def begin_close(self) -> None:
        """Quiesce: requests already inside a session finish; later ones get 423.

        Taking db_lock guarantees every session that committed before this
        point is included in the final seal, and none can commit after it.
        """
        with self.db_lock:
            self.closing = True

    def abort_close(self) -> None:
        with self.db_lock:
            self.closing = False

    def seal_for_close(self) -> Sealed | None:
        """Final save before locking. Returns the sealed snapshot if it could
        not be written (so the caller can keep retrying), None if on disk.

        Raises if the database could not even be sealed: the caller must then
        keep the vault open rather than lose data.
        """
        with self._file_lock:
            if self._pending_deletes:
                self._force_save = True
            with self.db_lock:
                changed = self.dirty or self._change_marker() != self._saved_marker
            if not changed:
                return None
            self._force_save = False
            sealed, seq = self._seal()
            try:
                self._write_sealed(sealed)
            except OSError as exc:
                log.error("final save failed, keeping the encrypted snapshot in memory: %s", exc)
                return sealed
            self._after_save(sealed.generation, seq)
            if self._pending_deletes:  # one more save lets the last deletions be swept
                sealed2, seq2 = self._seal()
                try:
                    self._write_sealed(sealed2)
                    self._after_save(sealed2.generation, seq2)
                except OSError:
                    pass
            return None

    def close(self) -> None:
        """Drop the database and key material (call seal_for_close() first).

        Holds the file lock so an in-progress save (which uses the master key
        outside db_lock while encrypting) always completes before the key is
        wiped, and joins the saver thread.
        """
        if self.closed:
            return
        with self._save_cv:
            self._saver_stop = True
            self._save_cv.notify_all()
        with self._file_lock:
            with self.db_lock:
                self.closed = True
                self.engine.dispose()
                self._conn.close()
            crypto.wipe(self._mk)
        with self._save_cv:
            self._save_cv.notify_all()  # release group-commit waiters
        if threading.current_thread() is not self._saver:
            self._saver.join(timeout=5)
        self._dirlock.release()


class BlobWriter:
    """write() chunks, then commit() -> (blob_id, blob_key, sha256_hex, size)."""

    def __init__(self, vault: OpenVault, limit: int | None):
        self.blob_id = uuid.uuid4().hex
        self.key = crypto.new_blob_key()
        self.limit = limit
        self._final = vault._blob_path(self.blob_id)
        new_dir = not self._final.parent.exists()
        self._final.parent.mkdir(parents=True, exist_ok=True)
        if new_dir:
            durable.fsync_dir(self._final.parent.parent)
        self._tmp = self._final.with_name(f".{self.blob_id}.tmp")
        self._fh = open(self._tmp, "wb")
        self._enc = crypto.BlobEncryptor(self.key, bytes.fromhex(self.blob_id), self._fh)
        self._done = False

    @property
    def size(self) -> int:
        return self._enc.size

    def write(self, data: bytes) -> None:
        self._enc.write(data)
        if self.limit is not None and self._enc.size > self.limit:
            self.abort()
            raise ValueError("file exceeds the upload limit")

    def commit(self) -> tuple[str, bytes, str, int]:
        sha = self._enc.finish()
        durable.fsync_file(self._fh)
        self._fh.close()
        durable.replace(self._tmp, self._final)
        durable.fsync_dir(self._final.parent)  # the rename must be durable before the row is
        self._done = True
        return self.blob_id, self.key, sha, self._enc.size

    def abort(self) -> None:
        if self._done:
            return
        self._done = True
        try:
            self._fh.close()
        finally:
            self._tmp.unlink(missing_ok=True)


# =============================================================== snapshots


def write_snapshot_file(path: Path, sealed: Sealed, *, rotate_bak: bool = True) -> None:
    """Durably install ``sealed`` as db.enc without ever leaving no db.enc.

    1. write db.enc.<gen>.tmp and fsync (a unique name: never truncates a file
       that might be the only copy of a recovered generation)
    2. hard-link the current db.enc to db.enc.bak (db.enc keeps existing)
    3. rename the tmp over db.enc; fsync the directory
    4. remove older stray tmps
    """
    tmp = path / f"db.enc.{sealed.generation}.tmp"
    try:
        with open(tmp, "wb") as fh:
            fh.write(sealed.ciphertext)
            durable.fsync_file(fh)
        cur = path / DB_FILE
        if rotate_bak and cur.exists():
            staged = path / "db.enc.bak.new"
            durable.unlink(staged)
            durable.link_or_copy(cur, staged)
            durable.replace(staged, path / DB_BAK)
        durable.replace(tmp, cur)
        durable.fsync_dir(path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    for stray in path.glob("db.enc.*.tmp"):
        m = _TMP_RE.match(stray.name)
        if m and int(m.group(1)) < sealed.generation:
            durable.unlink(stray)


def _candidates(path: Path) -> list[_Candidate]:
    found = []
    names = [DB_FILE, DB_BAK] + [p.name for p in path.glob("db.enc.*.tmp")]
    for name in names:
        p = path / name
        try:
            with open(p, "rb") as fh:
                head = fh.read(crypto.SNAPSHOT_HEADER_LEN + crypto.TAG_LEN)
        except OSError:
            continue
        if head[:4] == crypto.SNAPSHOT_MAGIC and len(head) > 4 and head[4] > crypto.SNAPSHOT_VERSION:
            raise NewerVersion("this vault was saved by a newer version of OffsecHub; please upgrade")
        try:
            gen = crypto.peek_snapshot_generation(head)
        except CryptoError:
            gen = -1
        if p.exists():
            source = "tmp" if name.endswith(".tmp") else name
            found.append(_Candidate(source, p, gen))
    return sorted(found, key=lambda c: c.generation, reverse=True)


@dataclass
class _Loaded:
    generation: int
    data: bytes
    source: str
    max_seen: int
    warnings: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    db_enc_trusted: bool = True


def _load_snapshot(path: Path, vault_id: bytes, mk: bytearray, pending: Sealed | None) -> _Loaded | None:
    """Authenticate candidates newest-first and stop at the first that verifies."""
    cands = _candidates(path)
    max_seen = max([c.generation for c in cands] + [pending.generation if pending else -1])
    options: list[tuple[int, str, object]] = [(c.generation, c.source, c) for c in cands]
    if pending is not None:
        options.append((pending.generation, "memory", pending))
    options.sort(key=lambda o: o[0], reverse=True)
    failed_db_enc = False
    for _gen, source, item in options:
        try:
            blob = item.ciphertext if isinstance(item, Sealed) else item.path.read_bytes()
            gen, data = crypto.decrypt_snapshot(mk, vault_id, blob)
        except (OSError, CryptoError):
            if source == DB_FILE:
                failed_db_enc = True
            continue
        loaded = _Loaded(gen, data, source, max_seen)
        if source == "tmp":
            loaded.notices.append("Recovered changes from an interrupted save.")
        elif source == "memory":
            loaded.notices.append("Recovered changes that could not be written to disk earlier.")
        elif source == DB_BAK:
            loaded.warnings.append(
                "The main database file was missing or failed its integrity check; the vault was "
                "opened from its backup and the most recent changes may be missing.")
        if failed_db_enc:
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            if source == DB_BAK:
                quarantined = path / f"db.enc.corrupt-{stamp}"
                durable.replace(path / DB_FILE, quarantined)
                loaded.warnings.append(f"A damaged or tampered database file was set aside as {quarantined.name}.")
        # Only a db.enc we authenticated may be rotated into .bak on the next save.
        loaded.db_enc_trusted = source == DB_FILE
        return loaded
    return None


# ================================================================== manager


class VaultManager:
    """Process-wide vault state: none → unlocked ⇄ locked."""

    def __init__(self, appconfig: AppConfig | None = None):
        self.config = appconfig or AppConfig()
        self._state_lock = threading.RLock()
        self.current: OpenVault | None = None
        self.locked_path: Path | None = None
        self.lock_reason: str | None = None
        self.last_activity = time.monotonic()
        self.auto_lock_minutes = DEFAULT_AUTO_LOCK_MIN
        self._on_unlock: list = []
        self._pending: dict[str, Sealed] = {}  # resolved vault path -> unsaved sealed snapshot
        self._stop = threading.Event()
        self._timer = threading.Thread(target=self._background_loop, name="vault-autolock", daemon=True)
        self._timer.start()

    def on_unlock(self, fn) -> None:
        """Register a hook run right after create/unlock (schema, settings)."""
        self._on_unlock.append(fn)

    # ---------------------------------------------------------------- state

    @property
    def state(self) -> str:
        if self.current is not None:
            return "unlocked"
        return "locked" if self.locked_path else "none"

    def require(self) -> OpenVault:
        v = self.current
        if v is None or v.closed:
            raise VaultLocked()
        return v

    def touch(self) -> None:
        self.last_activity = time.monotonic()

    def seconds_until_auto_lock(self) -> int | None:
        if self.current is None or not self.auto_lock_minutes:
            return None
        return max(0, int(self.auto_lock_minutes * 60 - (time.monotonic() - self.last_activity)))

    def status(self) -> dict:
        v = self.current
        path = v.path if v else self.locked_path
        pending = self._pending.get(str(path.resolve())) if path else None
        size = v.last_db_bytes if v else None
        warnings = list(v.warnings) if v else []
        if size and size > SIZE_WARNING_BYTES:
            warnings.append(f"This vault's database is {size // (1024 * 1024)} MB. Consider splitting "
                            "old engagements into a separate vault (export/backup) to keep saves fast.")
        return {
            "state": self.state,
            "path": str(path) if path else None,
            "name": path.name.removesuffix(".ohvault") if path else None,
            "auto_lock_minutes": self.auto_lock_minutes,
            "seconds_until_lock": self.seconds_until_auto_lock(),
            "lock_reason": self.lock_reason if v is None else None,
            "must_set_password": bool(v and v.must_set_password),
            "warnings": warnings,
            "notices": list(v.notices) if v else [],
            "dirty": bool(v and v.dirty),
            "last_saved_at": v.last_saved_at.isoformat() if v and v.last_saved_at else None,
            "save_error": (v.last_save_error if v else None)
            or ("Some changes could not be written to disk yet; OffsecHub keeps retrying." if pending else None),
            "db_bytes": size,
        }

    # ------------------------------------------------------------ lifecycle

    def create(self, path: Path, password: str) -> RecoveryInfo:
        """Create a new vault at ``path`` and unlock it."""
        validate_password(password)
        path = Path(path).expanduser()
        if path.suffix != ".ohvault":
            path = path.with_name(path.name + ".ohvault")
        if path.exists() and (not path.is_dir() or any(path.iterdir())):
            raise VaultError(f"{path} already exists and is not empty")
        with self._state_lock:
            self.lock()
            path.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(path, 0o700)
            except OSError:
                pass
            (path / BLOB_DIR).mkdir(exist_ok=True)
            header = VaultHeader.new()
            mk = bytearray(crypto.random_bytes(crypto.KEY_LEN))
            header.replace_slot(make_password_slot(header.vault_id, mk, password))
            slot, recovery = make_recovery_slot(header.vault_id, mk)
            header.replace_slot(slot)
            header.save(path, mk)
            dirlock = DirLock(path)
            dirlock.acquire()
            vault = self._open(path, header, mk, _new_sqlite(), 0, dirlock, "create", persisted=False)
            vault.notices += _location_notices(path)
            vault._store_header_copy()
            vault.save()  # the first snapshot is on disk before we return
            return RecoveryInfo(recovery, make_kit(header.vault_id, slot))

    def unlock(self, path: Path, password: str | None = None, recovery_key: str | None = None,
               recovery_kit: dict | None = None) -> None:
        path = Path(path).expanduser()
        if not path.is_dir():
            raise VaultError(f"{path} is not an OffsecHub vault")
        if not password and not recovery_key:
            raise WrongSecret("password or recovery key required")
        with self._state_lock:
            if self.current is not None and self.current.path.resolve() == path.resolve():
                return
            dirlock = DirLock(path)
            dirlock.acquire()  # before reading or repairing anything (VaultInUse if taken)
            try:
                candidates = self._header_candidates(path, recovery_kit if recovery_key else None)
                mk = self._unwrap(candidates, password, recovery_key)
                vault_id = candidates[0].vault_id
                key = str(path.resolve())
                pending = self._pending.get(key)
                if pending is not None:
                    try:
                        write_snapshot_file(path, pending)
                        del self._pending[key]
                        pending = None
                    except OSError:
                        pass
                loaded = _load_snapshot(path, vault_id, mk, pending)
                if loaded is None:
                    crypto.wipe(mk)
                    raise VaultError("the vault database failed its integrity check (damaged or "
                                     "tampered with) and no intact backup copy is available")
                conn = _new_sqlite(loaded.data)
                if conn.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    conn.close()
                    crypto.wipe(mk)
                    raise VaultError("the vault database failed its integrity check")
                try:
                    header, header_warnings = reconcile(
                        [c for c in candidates if c.mac is not None], _db_header_copy(conn), mk)
                except VaultFormatError as exc:
                    conn.close()
                    crypto.wipe(mk)
                    raise VaultError(str(exc)) from None
            except BaseException:
                dirlock.release()
                raise

            self.lock()
            self._pending.pop(str(path.resolve()), None)
            via = "recovery" if recovery_key else "password"
            vault = self._open(path, header, mk, conn, loaded.generation, dirlock, via)
            # Never reuse a generation number (e.g. one held by a quarantined file).
            hwm = self.config.high_water(vault_id.hex()) or {}
            vault.generation = max(loaded.generation, loaded.max_seen)
            vault.db_enc_trusted = loaded.db_enc_trusted
            if loaded.source != DB_FILE:
                vault._mark_dirty(force=True)  # durably promote what was recovered
            vault.warnings += loaded.warnings + header_warnings
            vault.notices += loaded.notices + _location_notices(path)
            self._check_rollback(vault, loaded.generation, hwm)
            if header_warnings or not _header_copies_match(path, header):
                # Repair missing, stale or tampered copies from the authentic header.
                body = json.dumps(header.to_json(), indent=2).encode()
                for name in (HEADER_FILE, MIRROR_FILE):
                    atomic_write(path / name, body)
                durable.fsync_dir(path)
            if _db_header_copy(conn) != header.to_json():
                vault._store_header_copy()
            if password and header.password_slot_is_weak():
                header.replace_slot(make_password_slot(header.vault_id, mk, password))
                vault._save_header()

    def _header_candidates(self, path: Path, kit: dict | None) -> list[VaultHeader]:
        try:
            candidates = load_candidates(path)
        except NewerHeaderVersion as exc:
            raise NewerVersion(str(exc)) from None
        except VaultFormatError as exc:
            if kit is None:
                raise VaultError(f"{exc}. If you have the recovery kit, unlock with the recovery key "
                                 "and the kit to restore it.") from None
            candidates = []
        if kit is not None:
            try:
                if kit.get("format") != KIT_FORMAT or kit.get("version") != 1:
                    raise ValueError
                slot = Keyslot.from_json(kit["recovery_slot"])
                kit_header = VaultHeader(vault_id=bytes.fromhex(kit["vault_id"]), keyslots=[slot])
            except (KeyError, TypeError, ValueError, VaultFormatError):
                raise VaultError("that is not a valid OffsecHub recovery kit") from None
            if candidates and kit_header.vault_id != candidates[0].vault_id:
                raise VaultError("the recovery kit belongs to a different vault")
            candidates.append(kit_header)
        return candidates

    @staticmethod
    def _unwrap(candidates: list[VaultHeader], password: str | None, recovery_key: str | None) -> bytearray:
        last: Exception | None = None
        for header in candidates:  # primary, mirror, then the recovery kit
            try:
                if recovery_key:
                    return header.unlock_with_recovery(recovery_key)
                return header.unlock_with_password(password or "")
            except ValueError as exc:  # recovery-key typo: same for every copy
                raise WrongSecret(str(exc)) from None
            except CryptoError as exc:
                last = exc
        raise WrongSecret("wrong password or recovery key") from last

    def _check_rollback(self, vault: OpenVault, loaded_generation: int, record: dict) -> None:
        """Warn if this vault is older than the newest version this machine has seen."""
        if record and hmac.compare_digest(record.get("mac", ""),
                                          vault.high_water_mac(int(record.get("generation", 0)))):
            if loaded_generation < int(record["generation"]):
                vault.warnings.append(
                    "This vault is older than the last version opened on this computer "
                    f"(generation {loaded_generation} < {record['generation']}). It may have been "
                    "restored from an old backup or rolled back. If you restored a backup on "
                    "purpose, you can ignore this.")
                return
        self._record_high_water(vault)

    def _record_high_water(self, vault: OpenVault) -> None:
        try:
            self.config.set_high_water(vault.vault_id.hex(), vault.generation,
                                       vault.high_water_mac(vault.generation))
        except OSError:
            log.warning("could not record vault high-water mark")

    def _open(self, path, header, mk, conn, generation, dirlock, via, persisted=True) -> OpenVault:
        vault = OpenVault(path, header, mk, conn, generation, dirlock, via, persisted)
        self.current = vault
        self.locked_path = None
        self.lock_reason = None
        self.touch()
        try:
            for fn in self._on_unlock:
                fn(vault)
        except BaseException:
            self.current = None
            vault.close()
            raise
        self.config.add_recent(path)
        return vault

    def lock(self, reason: str = "manual") -> None:
        """Seal and close the open vault. Never discards data:

        * sealing fails (e.g. out of memory)  → the vault stays unlocked (raises)
        * writing fails (disk full, drive gone) → the vault locks, the encrypted
          snapshot stays in memory and is retried in the background
        """
        with self._state_lock:
            v = self.current
            if v is None:
                return
            v.begin_close()
            try:
                sealed = v.seal_for_close()
            except VaultLocked:
                sealed = None
            except Exception as exc:
                v.abort_close()
                v.last_save_error = f"Could not save the vault, so it was left unlocked: {exc}"
                raise VaultError(v.last_save_error) from exc
            self._record_high_water(v)
            self.current = None
            self.locked_path = v.path
            self.lock_reason = reason
            if sealed is not None:
                self._pending[str(v.path.resolve())] = sealed
            v.close()

    def forget(self) -> None:
        """Lock and forget which vault was open (back to the vault picker)."""
        with self._state_lock:
            self.lock()
            self.locked_path = None
            self.lock_reason = None

    def shutdown(self) -> None:
        self._stop.set()
        try:
            self.lock(reason="exit")
        finally:
            self._flush_pending(final=True)

    # ------------------------------------------------------- background jobs

    def _flush_pending(self, final: bool = False) -> None:
        for key, sealed in list(self._pending.items()):
            path = Path(key)
            try:
                write_snapshot_file(path, sealed)
                del self._pending[key]
                log.info("wrote a previously unsaved snapshot to %s", path)
            except OSError as exc:
                if final:
                    # Ciphertext needs no key to be safe: park it where we can write.
                    rescue = self.config.dir / "unsaved" / f"{path.name}-gen{sealed.generation}.db.enc"
                    try:
                        rescue.parent.mkdir(parents=True, exist_ok=True)
                        rescue.write_bytes(sealed.ciphertext)
                        log.error("could not save %s (%s); an encrypted copy of the latest changes was "
                                  "written to %s. Copy it into the vault as db.enc to restore.", path, exc, rescue)
                    except OSError:
                        log.critical("could not save %s and could not write a rescue copy", path)

    def _background_loop(self) -> None:
        while not self._stop.wait(2):
            if self._pending:
                self._flush_pending()
            if self.seconds_until_auto_lock() == 0:
                log.info("auto-locking idle vault")
                try:
                    self.lock(reason="idle")
                except Exception:
                    log.exception("auto-lock postponed")
                    self.touch()  # retry after another idle period instead of spinning
