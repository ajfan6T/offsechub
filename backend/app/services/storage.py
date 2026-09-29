"""Evidence file storage on local disk, addressed by random keys.

Files are never stored under a user-supplied name, so upload paths cannot be
used for traversal. Swap this module for an S3/MinIO backend in production.
"""

import hashlib
import mimetypes
import re
import uuid
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Evidence

# Raster images are safe to render inline; everything else (incl. SVG, HTML) is
# served as an attachment so uploaded content can never execute in our origin.
INLINE_IMAGE_TYPES = {"image/png", "image/jpeg", "image/gif", "image/webp"}

_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._ -]+")


class UploadTooLarge(Exception):
    pass


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


def _path_for(key: str) -> Path:
    root = get_settings().storage_dir
    return root / key[:2] / key


def store_evidence(
    db: Session,
    *,
    engagement_id: int,
    filename: str,
    data: bytes,
    content_type: str | None,
    uploaded_by_id: int | None,
    description: str = "",
    finding_id: int | None = None,
    target_id: int | None = None,
    test_case_id: int | None = None,
) -> Evidence:
    max_bytes = get_settings().max_upload_mb * 1024 * 1024
    if len(data) > max_bytes:
        raise UploadTooLarge(f"file exceeds {get_settings().max_upload_mb} MB limit")

    key = uuid.uuid4().hex
    path = _path_for(key)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

    safe_name = sanitize_filename(filename)
    ev = Evidence(
        engagement_id=engagement_id,
        filename=safe_name,
        content_type=guess_content_type(safe_name, content_type),
        size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        storage_key=key,
        description=description,
        finding_id=finding_id,
        target_id=target_id,
        test_case_id=test_case_id,
        uploaded_by_id=uploaded_by_id,
    )
    db.add(ev)
    db.flush()
    return ev


def read_evidence(ev: Evidence) -> bytes:
    return _path_for(ev.storage_key).read_bytes()


def delete_evidence_file(ev: Evidence) -> None:
    _path_for(ev.storage_key).unlink(missing_ok=True)
