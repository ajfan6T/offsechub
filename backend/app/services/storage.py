"""Evidence storage: encrypted blobs in the vault, metadata rows in its database.

Every file is encrypted with its own random key (``Evidence.blob_key``), which
exists only inside the encrypted database, so deleting the row
cryptographically erases the file. Blobs are addressed by random ids, never by
user-supplied names, so filenames cannot be used for path traversal.
"""

import mimetypes
import re
from collections.abc import AsyncIterable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..config import get_settings
from ..models import Evidence
from ..vault.manager import OpenVault, VaultLocked

# Raster images are safe to render inline; everything else (incl. SVG, HTML) is
# served as an attachment so uploaded content can never execute in our origin.
INLINE_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._ -]+")


class UploadTooLarge(Exception):
    pass


class EmptyUpload(Exception):
    pass


@dataclass(frozen=True)
class StoredBlob:
    """A blob that has been written to the vault but may not have a row yet."""

    blob_id: str
    key: bytes
    sha256: str
    size: int


def upload_limit() -> int:
    return get_settings().max_upload_mb * 1024 * 1024


def _too_large() -> UploadTooLarge:
    return UploadTooLarge(f"File exceeds the {get_settings().max_upload_mb} MB upload limit")


def check_size(size: int) -> None:
    if size > upload_limit():
        raise _too_large()


def sanitize_filename(name: str) -> str:
    name = Path(name.replace("\\", "/")).name
    name = _UNSAFE_CHARS.sub("_", name).strip(" .")
    return name[:200] or "evidence.bin"


def guess_content_type(filename: str, declared: str | None) -> str:
    guessed, _ = mimetypes.guess_type(filename)
    ctype = (declared or "").split(";")[0].strip().lower()
    if not ctype or ctype == "application/octet-stream":
        ctype = guessed or "application/octet-stream"
    return ctype[:100]


# ------------------------------------------------------------------ writing


def write_bytes(vault: OpenVault, data: bytes) -> StoredBlob:
    """Encrypt an in-memory file into a new blob."""
    check_size(len(data))
    return StoredBlob(*vault.write_blob(data))


async def receive_blob(vault: OpenVault, chunks: AsyncIterable[bytes]) -> StoredBlob:
    """Encrypt an async byte stream (an HTTP body) into a new blob.

    Only one chunk is in memory at a time and plaintext never touches disk.
    Nothing is left behind if the stream fails, is too large or is empty, or
    if the vault is locked meanwhile.
    """
    writer = vault.open_blob_writer(upload_limit())
    try:
        async for chunk in chunks:
            if vault.closed:  # locked mid-upload: stop accepting plaintext
                raise VaultLocked()
            try:
                # Encrypting 64 KiB is cheaper than a thread hop, so stay on the loop.
                writer.write(chunk)
            except ValueError:  # the writer's size limit
                raise _too_large() from None
        if writer.size == 0:
            raise EmptyUpload("Empty file")
        # commit() fsyncs, which can block for a while: keep it off the event loop.
        return StoredBlob(*await run_in_threadpool(writer.commit))
    finally:
        writer.abort()  # no-op after a successful commit


async def receive_bytes(chunks: AsyncIterable[bytes]) -> bytes:
    """Read an async byte stream into memory, enforcing the upload limit as it arrives."""
    buf = bytearray()
    async for chunk in chunks:
        buf += chunk
        check_size(len(buf))
    return bytes(buf)


@contextmanager
def discard_on_error(vault: OpenVault, blob: StoredBlob) -> Iterator[None]:
    """Delete ``blob`` again if the block fails, e.g. before its row is committed."""
    try:
        yield
    except BaseException:
        vault.delete_blob(blob.blob_id)
        raise


def add_evidence(
    db: Session,
    blob: StoredBlob,
    *,
    engagement_id: int,
    filename: str,
    content_type: str | None,
    description: str = "",
    finding_id: int | None = None,
    target_id: int | None = None,
    test_case_id: int | None = None,
) -> Evidence:
    """Insert the row that owns ``blob`` (flushed, not committed)."""
    safe_name = sanitize_filename(filename)
    ev = Evidence(
        engagement_id=engagement_id,
        filename=safe_name,
        content_type=guess_content_type(safe_name, content_type),
        size=blob.size,
        sha256=blob.sha256,
        storage_key=blob.blob_id,
        blob_key=blob.key,
        description=description,
        finding_id=finding_id,
        target_id=target_id,
        test_case_id=test_case_id,
    )
    db.add(ev)
    db.flush()
    return ev


# ------------------------------------------------------------------ reading


def stream_evidence(vault: OpenVault, ev: Evidence) -> Iterator[bytes]:
    """Decrypted chunks; raises at the end if size or fingerprint do not match.

    Raises FileNotFoundError up front if the blob is missing.
    """
    chunks = vault.read_blob(ev.storage_key, ev.blob_key, sha256=ev.sha256, size=ev.size)

    def guarded() -> Iterator[bytes]:
        for chunk in chunks:
            if vault.closed:  # locking the vault also stops downloads in flight
                raise VaultLocked()
            yield chunk

    return guarded()


def read_evidence(vault: OpenVault, ev: Evidence) -> bytes:
    return vault.read_blob_bytes(ev.storage_key, ev.blob_key, sha256=ev.sha256, size=ev.size)


# ----------------------------------------------------------------- deleting


def delete_blobs(vault: OpenVault, blob_ids: Iterable[str]) -> None:
    """Schedule the files of deleted evidence rows for removal.

    Call only after the deletion is committed: a failed commit must not lose
    files. The vault removes them once no retained snapshot references them.
    """
    for blob_id in blob_ids:
        vault.delete_blob(blob_id)
