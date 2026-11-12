"""Engagement hand-off files: one engagement, encrypted under a passphrase.

OffsecHub is single-operator. To pass an engagement to a colleague (or move it
to another vault), export it to a ``.ohengagement`` file, send the file, and
share the passphrase over a different channel. docs/VAULT_FORMAT.md §9 is the
normative description; in short:

    header  "OHEX" | version 1 | Argon2id m_kib (u32) | t (u8) | p (u8) | salt (32) | chunk size (u32)
    key     HKDF-SHA256(Argon2id(passphrase, salt), info "offsechub/v1/handoff")
    body    STREAM (AES-256-GCM, 64 KiB chunks, header as associated data) over:
              u32 manifest length | manifest JSON | each evidence file's bytes, in manifest order

Export streams evidence from the vault's encrypted blobs straight into the
hand-off encryptor, and import streams it back into new blobs: plaintext never
touches disk. Import treats the file as untrusted: the KDF parameters are
checked before Argon2 runs, the manifest is validated field by field, every
evidence file must match its recorded size and SHA-256, and nothing is added
to the vault unless the whole file authenticates and parses.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
from collections.abc import Iterator
from datetime import date, datetime, timezone
from pathlib import Path
from typing import BinaryIO, Literal

from pydantic import BaseModel, Field, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import __version__
from ..models import (
    Client,
    Engagement,
    Evidence,
    Finding,
    FindingRetest,
    OperatorLogEntry,
    ReconImport,
    ScopeItem,
    Service,
    Target,
    TestCase,
)
from ..schemas import (
    EngagementStatus,
    EngagementType,
    FindingStatus,
    OplogOutcome,
    RetestResult,
    ScopeKind,
    ScopeRule,
    Severity,
    TargetStatus,
    TestStatus,
)
from ..vault import crypto, durable
from ..vault.crypto import Argon2Params, CryptoError
from ..vault.manager import MIN_PASSWORD, OpenVault
from . import audit, storage

MAGIC = b"OHEX"
VERSION = 1
FORMAT = "offsechub-engagement"
SUFFIX = ".ohengagement"
_HEADER = struct.Struct(">4sBIBB32sI")  # magic, version, m_kib, t, p, salt, chunk_size
HEADER_LEN = _HEADER.size  # 47
_INFO = b"offsechub/v1/handoff"
MAX_MANIFEST = 64 * 1024 * 1024


class HandoffError(Exception):
    """Shown to the user; deliberately unspecific about why decryption failed."""


# ------------------------------------------------------------------ manifest
# Explicit, validated models: an imported file is untrusted input.

S = Field(default="", max_length=255)
T = Field(default="", max_length=1_000_000)


class _Service(BaseModel):
    port: int = Field(ge=0, le=65535)
    protocol: Literal["tcp", "udp", "sctp"] = "tcp"
    state: str = Field(default="open", max_length=20)
    name: str = Field(default="", max_length=100)
    product: str = S
    version: str = S
    extra_info: str = T


class _Target(BaseModel):
    id: int
    kind: str = Field(default="host", max_length=20)
    value: str = Field(min_length=1, max_length=512)
    hostname: str = S
    ip: str = Field(default="", max_length=64)
    os: str = S
    status: TargetStatus = "new"
    tags: list[str] = Field(default_factory=list, max_length=200)
    notes: str = T
    source: str = Field(default="manual", max_length=50)
    services: list[_Service] = Field(default_factory=list, max_length=70_000)


class _Retest(BaseModel):
    tested_on: date
    result: RetestResult
    tester: str = S
    notes: str = T


class _Finding(BaseModel):
    id: int
    number: int = Field(ge=1)
    title: str = Field(min_length=1, max_length=255)
    severity: Severity
    status: FindingStatus
    cvss_vector: str = Field(default="", max_length=512)
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cwe: str = Field(default="", max_length=20)
    description: str = T
    impact: str = T
    steps_to_reproduce: str = T
    remediation: str = T
    references: str = T
    source: str = Field(default="manual", max_length=50)
    source_ref: str = Field(default="", max_length=512)
    targets: list[int] = Field(default_factory=list)
    retests: list[_Retest] = Field(default_factory=list)


class _TestCase(BaseModel):
    id: int
    methodology: str = Field(default="custom", max_length=100)
    ref: str = Field(default="", max_length=50)
    category: str = Field(default="General", max_length=100)
    title: str = Field(min_length=1, max_length=255)
    description: str = T
    status: TestStatus = "not_started"
    notes: str = T
    target: int | None = None
    finding: int | None = None


class _Oplog(BaseModel):
    occurred_at: datetime
    operator: str = S
    source_host: str = S
    target: str = Field(default="", max_length=512)
    tool: str = Field(default="", max_length=100)
    command: str = T
    description: str = T
    outcome: OplogOutcome = "info"


class _Evidence(BaseModel):
    id: int
    filename: str = Field(min_length=1, max_length=255)
    content_type: str = Field(default="application/octet-stream", max_length=100)
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    description: str = T
    finding: int | None = None
    target: int | None = None
    test_case: int | None = None
    created_at: datetime


class _Import(BaseModel):
    tool: str = Field(max_length=30)
    filename: str = S
    stats: dict = Field(default_factory=dict)
    evidence: int | None = None
    created_at: datetime


class _Client(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    industry: str = Field(default="", max_length=100)
    contact_name: str = S
    contact_email: str = S
    notes: str = T


class _Engagement(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    code: str = Field(min_length=1, max_length=32)
    type: EngagementType
    status: EngagementStatus
    start_date: date | None = None
    end_date: date | None = None
    description: str = T
    rules_of_engagement: str = T
    executive_summary: str = T


class _Scope(BaseModel):
    kind: ScopeKind
    value: str = Field(min_length=1, max_length=512)
    rule: ScopeRule = "include"
    notes: str = T


class Manifest(BaseModel):
    format: Literal["offsechub-engagement"]
    version: Literal[1]
    created_at: datetime
    app_version: str = Field(max_length=32)
    client: _Client
    engagement: _Engagement
    scope: list[_Scope] = Field(default_factory=list, max_length=100_000)
    targets: list[_Target] = Field(default_factory=list, max_length=200_000)
    findings: list[_Finding] = Field(default_factory=list, max_length=100_000)
    test_cases: list[_TestCase] = Field(default_factory=list, max_length=100_000)
    oplog: list[_Oplog] = Field(default_factory=list, max_length=1_000_000)
    evidence: list[_Evidence] = Field(default_factory=list, max_length=100_000)
    imports: list[_Import] = Field(default_factory=list, max_length=100_000)


BlobRef = tuple[str, bytes, str, int]  # storage key, blob key, sha256, size


def build_manifest(eng: Engagement) -> tuple[dict, list[BlobRef]]:
    """The manifest dict and the blobs whose bytes follow it, in order."""
    evidence = sorted(eng.evidence, key=lambda e: e.id)
    c = eng.client
    manifest = {
        "format": FORMAT,
        "version": VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "app_version": __version__,
        "client": {k: getattr(c, k) for k in ("name", "industry", "contact_name", "contact_email", "notes")},
        "engagement": {
            **{k: getattr(eng, k) for k in ("name", "code", "type", "status", "description",
                                            "rules_of_engagement", "executive_summary")},
            "start_date": eng.start_date.isoformat() if eng.start_date else None,
            "end_date": eng.end_date.isoformat() if eng.end_date else None,
        },
        "scope": [{"kind": s.kind, "value": s.value, "rule": s.rule, "notes": s.notes} for s in eng.scope_items],
        "targets": [
            {"id": t.id, **{k: getattr(t, k) for k in ("kind", "value", "hostname", "ip", "os", "status",
                                                       "tags", "notes", "source")},
             "services": [{k: getattr(s, k) for k in ("port", "protocol", "state", "name", "product", "version",
                                                      "extra_info")} for s in t.services]}
            for t in eng.targets
        ],
        "findings": [
            {"id": f.id, **{k: getattr(f, k) for k in (
                "number", "title", "severity", "status", "cvss_vector", "cvss_score", "cwe", "description",
                "impact", "steps_to_reproduce", "remediation", "references", "source", "source_ref")},
             "targets": [t.id for t in f.targets],
             "retests": [{"tested_on": r.tested_on.isoformat(), "result": r.result, "tester": r.tester,
                          "notes": r.notes} for r in f.retests]}
            for f in eng.findings
        ],
        "test_cases": [
            {"id": tc.id, **{k: getattr(tc, k) for k in ("methodology", "ref", "category", "title", "description", "status",
                                            "notes")},
             "target": tc.target_id, "finding": tc.finding_id}
            for tc in eng.test_cases
        ],
        "oplog": [
            {**{k: getattr(o, k) for k in ("operator", "source_host", "target", "tool", "command", "description",
                                           "outcome")},
             "occurred_at": o.occurred_at.isoformat()}
            for o in eng.oplog
        ],
        "evidence": [
            {"id": e.id, "filename": e.filename, "content_type": e.content_type, "size": e.size, "sha256": e.sha256,
             "description": e.description, "finding": e.finding_id, "target": e.target_id,
             "test_case": e.test_case_id, "created_at": e.created_at.isoformat()}
            for e in evidence
        ],
        "imports": [
            {"tool": i.tool, "filename": i.filename, "stats": i.stats, "evidence": i.evidence_id,
             "created_at": i.created_at.isoformat()}
            for i in eng.imports
        ],
    }
    return manifest, [(e.storage_key, bytes(e.blob_key), e.sha256, e.size) for e in evidence]


# ------------------------------------------------------------------ crypto


def _key(passphrase: str, salt: bytes, params: Argon2Params) -> bytearray:
    kek = crypto.derive_password_kek(passphrase, salt, params)
    try:
        return crypto.hkdf(kek, b"", _INFO)
    finally:
        crypto.wipe(kek)


def check_passphrase(passphrase: str) -> None:
    if len(passphrase) < MIN_PASSWORD:
        raise HandoffError(f"the passphrase must be at least {MIN_PASSWORD} characters")


def write_handoff(vault: OpenVault, manifest: dict, blobs: list[BlobRef], passphrase: str,
                  dest: Path, params: Argon2Params) -> int:
    """Encrypt the engagement into ``dest`` (a new file); returns its size in bytes.

    Needs no DB session: the manifest and blob references were taken beforehand.
    """
    check_passphrase(passphrase)
    if not dest.parent.is_dir():
        raise HandoffError(f"the folder {dest.parent} does not exist")
    if dest.exists():
        raise HandoffError(f"{dest} already exists")
    salt = crypto.random_bytes(crypto.SALT_LEN)
    header = _HEADER.pack(MAGIC, VERSION, params.m_kib, params.t, params.p, salt, crypto.CHUNK_SIZE)
    key = _key(passphrase, salt, params)
    body = json.dumps(manifest, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    tmp = dest.with_name(f".{dest.name}.{os.getpid()}.tmp")
    try:
        with open(tmp, "xb") as fh:
            enc = crypto.StreamEncryptor(key, header, fh)
            enc.write(struct.pack(">I", len(body)))
            enc.write(body)
            for storage_key, blob_key, sha256, size in blobs:
                for chunk in vault.read_blob(storage_key, blob_key, sha256=sha256, size=size):
                    enc.write(chunk)
            enc.finish()
            durable.fsync_file(fh)
        durable.replace(tmp, dest)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    finally:
        crypto.wipe(key)
    return dest.stat().st_size


class _Reader:
    """read(n) over an iterator of decrypted chunks."""

    def __init__(self, chunks: Iterator[bytes]):
        self._chunks = chunks
        self._buf = bytearray()

    def read(self, n: int) -> bytes:
        while len(self._buf) < n:
            try:
                self._buf += next(self._chunks)
            except StopIteration:
                break
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def stream(self, n: int, size: int = crypto.CHUNK_SIZE) -> Iterator[bytes]:
        while n > 0:
            piece = self.read(min(n, size))
            if not piece:
                raise HandoffError("the file is truncated")
            n -= len(piece)
            yield piece

    def at_end(self) -> bool:
        return not self.read(1)


def read_handoff(vault: OpenVault, src: BinaryIO, passphrase: str
                 ) -> tuple[Manifest, dict[int, storage.StoredBlob]]:
    """Decrypt and validate a hand-off file, storing its evidence as new vault blobs.

    Returns the manifest and the new blob for each evidence id. On any error
    the blobs written so far are deleted and HandoffError is raised.
    """
    header = src.read(HEADER_LEN)
    if len(header) != HEADER_LEN:
        raise HandoffError("this is not an OffsecHub hand-off file")
    magic, version, m_kib, t, p, salt, chunk_size = _HEADER.unpack(header)
    if magic != MAGIC or chunk_size != crypto.CHUNK_SIZE:
        raise HandoffError("this is not an OffsecHub hand-off file")
    if version != VERSION:
        raise HandoffError("this hand-off file needs a newer version of OffsecHub")
    params = Argon2Params(m_kib=m_kib, t=t, p=p)
    try:
        params.validate()  # before Argon2 runs: these values drive memory and time
    except CryptoError:
        raise HandoffError("this hand-off file has unsupported key settings") from None
    key = _key(passphrase, salt, params)
    blobs: dict[int, storage.StoredBlob] = {}
    try:
        reader = _Reader(crypto.stream_decrypt(key, header, src))
        try:
            (length,) = struct.unpack(">I", reader.read(4))
        except struct.error:
            raise HandoffError("the passphrase is wrong or the file is damaged") from None
        if length > MAX_MANIFEST:
            raise HandoffError("the file is damaged")
        try:
            manifest = Manifest.model_validate_json(reader.read(length))
        except ValidationError as exc:
            raise HandoffError(f"the file's contents are not valid: {exc.error_count()} problem(s), e.g. "
                               f"{exc.errors()[0]['loc']}: {exc.errors()[0]['msg']}") from None
        for ev in manifest.evidence:
            writer = vault.open_blob_writer(ev.size)
            try:
                sha = hashlib.sha256()
                for piece in reader.stream(ev.size):
                    sha.update(piece)
                    writer.write(piece)
                if sha.hexdigest() != ev.sha256:
                    raise HandoffError(f"evidence {ev.filename} does not match its fingerprint")
                blobs[ev.id] = storage.StoredBlob(*writer.commit())
            finally:
                writer.abort()  # no-op after commit
        if not reader.at_end():
            raise HandoffError("the file is damaged")
        return manifest, blobs
    except CryptoError:
        storage.delete_blobs(vault, [b.blob_id for b in blobs.values()])
        raise HandoffError("the passphrase is wrong or the file is damaged") from None
    except BaseException:
        storage.delete_blobs(vault, [b.blob_id for b in blobs.values()])
        raise
    finally:
        crypto.wipe(key)


def spool() -> BinaryIO:
    """An anonymous temp file for an uploaded hand-off (it only ever holds ciphertext)."""
    return tempfile.TemporaryFile(prefix="offsechub-handoff-")


# ------------------------------------------------------------------ import


def _free_code(db: Session, code: str) -> str:
    taken = set(db.scalars(select(Engagement.code)))
    if code not in taken:
        return code
    for n in range(2, 1000):
        candidate = f"{code[:28]}-{n}"
        if candidate not in taken:
            return candidate
    raise HandoffError("could not find a free engagement code")


def apply_manifest(db: Session, m: Manifest, blobs: dict[int, storage.StoredBlob]) -> Engagement:
    """Create the engagement (and its client if new) from a validated manifest. Flushes, no commit."""
    client = db.scalar(select(Client).where(Client.name == m.client.name))
    if client is None:
        client = Client(**m.client.model_dump())
        db.add(client)
        db.flush()
    eng = Engagement(client_id=client.id, **{**m.engagement.model_dump(), "code": _free_code(db, m.engagement.code)})
    db.add(eng)
    db.flush()
    for s in m.scope:
        db.add(ScopeItem(engagement_id=eng.id, **s.model_dump()))

    targets: dict[int, Target] = {}
    seen_values: set[str] = set()
    for t in m.targets:
        if t.value in seen_values:
            raise HandoffError(f"duplicate target {t.value}")
        seen_values.add(t.value)
        data = t.model_dump(exclude={"id", "services"})
        target = Target(engagement_id=eng.id, **data,
                        services=[Service(**s.model_dump()) for s in
                                  {(s.port, s.protocol): s for s in t.services}.values()])
        db.add(target)
        targets[t.id] = target
    db.flush()

    def target_id(old: int | None) -> int | None:
        if old is None:
            return None
        if old not in targets:
            raise HandoffError("the file refers to a target it does not contain")
        return targets[old].id

    findings: dict[int, Finding] = {}
    numbers: set[int] = set()
    for f in m.findings:
        if f.number in numbers:
            raise HandoffError(f"duplicate finding number {f.number}")
        numbers.add(f.number)
        finding = Finding(engagement_id=eng.id, **f.model_dump(exclude={"id", "targets", "retests"}))
        finding.targets = [targets[i] for i in dict.fromkeys(f.targets) if i in targets]
        if len(finding.targets) != len(set(f.targets)):
            raise HandoffError("the file refers to a target it does not contain")
        finding.retests = [FindingRetest(**r.model_dump()) for r in f.retests]
        db.add(finding)
        findings[f.id] = finding
    db.flush()

    def finding_id(old: int | None) -> int | None:
        if old is None:
            return None
        if old not in findings:
            raise HandoffError("the file refers to a finding it does not contain")
        return findings[old].id

    tests: dict[int, TestCase] = {}
    for tc in m.test_cases:
        row = TestCase(engagement_id=eng.id, **tc.model_dump(exclude={"id", "target", "finding"}),
                       target_id=target_id(tc.target), finding_id=finding_id(tc.finding))
        db.add(row)
        tests[tc.id] = row
    for o in m.oplog:
        db.add(OperatorLogEntry(engagement_id=eng.id, **o.model_dump()))
    db.flush()

    evidence: dict[int, Evidence] = {}
    for ev in m.evidence:
        row = storage.add_evidence(
            db, blobs[ev.id], engagement_id=eng.id, filename=ev.filename, content_type=ev.content_type,
            description=ev.description, finding_id=finding_id(ev.finding), target_id=target_id(ev.target),
            test_case_id=tests[ev.test_case].id if ev.test_case in tests else None)
        row.created_at = ev.created_at
        evidence[ev.id] = row
    for imp in m.imports:
        db.add(ReconImport(engagement_id=eng.id, tool=imp.tool, filename=imp.filename, stats=imp.stats,
                           evidence_id=evidence[imp.evidence].id if imp.evidence in evidence else None,
                           created_at=imp.created_at))
    db.flush()
    audit.record(db, action="import", entity_type="engagement", entity_id=eng.id, engagement_id=eng.id,
                 summary=f"Imported {eng.code} from a hand-off file ({len(m.findings)} findings, "
                         f"{len(m.evidence)} evidence files)")
    return eng
