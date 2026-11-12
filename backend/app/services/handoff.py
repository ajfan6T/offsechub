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
checked before Argon2 runs, the manifest is validated field by field (by the
API's rules), its ids must be unique and its links resolve, every evidence
file must match its recorded size and SHA-256, and nothing is added to the
vault unless the whole file authenticates and parses.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
from collections.abc import Hashable, Iterable, Iterator
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Annotated, BinaryIO, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator
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
    EngagementCode,
    EngagementStatus,
    EngagementType,
    FindingStatus,
    ImportTool,
    OplogOutcome,
    RetestResult,
    ScopeKind,
    ScopeRule,
    Severity,
    TargetKind,
    TargetStatus,
    TestStatus,
)
from ..vault import crypto, durable
from ..vault.crypto import Argon2Params, CryptoError
from ..vault.manager import MIN_PASSWORD, OpenVault
from . import audit, cvss, storage
from .scope import normalize_scope_value

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
# Explicit, validated models: an imported file is untrusted input. They mirror
# the API's input schemas field by field (the same Literal types and engagement
# code rule, from app.schemas) and admit everything the importers store, so an
# export from any vault imports and nothing is imported that the app could not
# show. Where the app sets no limit of its own, a string is bounded by MAX_TEXT.

MAX_TEXT = 1_000_000  # characters, for every string without a tighter limit
MAX_ITEMS = 1_000_000  # entries in any list (the 64 MiB manifest limit binds first)
NAME = 255  # the API's limit on names, titles, testers and operators
SOURCE = 50  # "manual", "template" or an import tool
Count = Annotated[int, Field(ge=0, le=2**53 - 1)]


def _items():
    return Field(default_factory=list, max_length=MAX_ITEMS)


class _Record(BaseModel):
    model_config = ConfigDict(str_max_length=MAX_TEXT)


class _Service(_Record):
    """ServiceIn, except that ``protocol`` is whatever a scan reported (Nmap "ip", Nessus "icmp")."""

    port: int = Field(ge=0, le=65535)
    protocol: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""


class _Target(_Record):
    """TargetIn plus what the app sets. Importers store values longer than the API's 512."""

    id: int
    kind: TargetKind = "host"
    value: str  # the API strips it, so even "" can be stored
    hostname: str = ""
    ip: str = ""
    os: str = ""
    status: TargetStatus = "new"
    tags: list[str] = _items()
    notes: str = ""
    source: str = Field(default="manual", max_length=SOURCE)
    services: list[_Service] = _items()


class _Retest(_Record):
    tested_on: date
    result: RetestResult
    tester: str = Field(default="", max_length=NAME)
    notes: str = ""


class _Finding(_Record):
    """FindingIn plus what the app sets (number, score, source, retests)."""

    id: int
    number: int = Field(ge=1, le=2**31 - 1)
    title: str = Field(min_length=1, max_length=NAME)
    severity: Severity
    status: FindingStatus
    cvss_vector: str = ""
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cwe: str = ""
    description: str = ""
    impact: str = ""
    steps_to_reproduce: str = ""
    remediation: str = ""
    references: str = ""
    source: str = Field(default="manual", max_length=SOURCE)
    source_ref: str = ""
    targets: list[int] = _items()
    retests: list[_Retest] = _items()

    @model_validator(mode="after")
    def _cvss(self) -> "_Finding":
        """As in the API: a vector must score, and the score is the vector's."""
        vector = self.cvss_vector.strip()
        if not vector:
            self.cvss_vector, self.cvss_score = "", None
            return self
        try:
            result = cvss.calculate(vector)
        except cvss.CvssError as exc:
            raise ValueError(f"invalid CVSS vector: {exc}") from None
        self.cvss_vector, self.cvss_score = result.vector, result.score
        return self


class _TestCase(_Record):
    """TestCaseIn; ``target`` and ``finding`` are manifest ids."""

    id: int
    methodology: str = "custom"
    ref: str = ""
    category: str = "General"
    title: str = Field(min_length=1, max_length=NAME)
    description: str = ""
    status: TestStatus = "not_started"
    notes: str = ""
    target: int | None = None
    finding: int | None = None


class _Oplog(_Record):
    occurred_at: datetime
    operator: str = Field(default="", max_length=NAME)
    source_host: str = ""
    target: str = ""
    tool: str = ""
    command: str = ""
    description: str = ""
    outcome: OplogOutcome = "info"


class _Evidence(_Record):
    """What the upload endpoints store (name and type are sanitised again on import)."""

    id: int
    filename: str = Field(min_length=1, max_length=NAME)
    content_type: str = Field(default="application/octet-stream", max_length=100)
    size: int = Field(ge=0)
    sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    description: str = ""
    finding: int | None = None
    target: int | None = None
    test_case: int | None = None
    created_at: datetime


class _ImportStats(_Record):
    """The counts a recon import records (importers/apply.py), as the Recon page reads them."""

    hosts_seen: Count = 0
    targets_created: Count = 0
    targets_updated: Count = 0
    services_created: Count = 0
    findings_created: Count = 0
    findings_updated: Count = 0
    skipped_out_of_scope: Count = 0
    skipped_excluded: Count = 0
    errors: list[str] = _items()


class _Import(_Record):
    tool: ImportTool
    filename: str = Field(default="", max_length=NAME)
    stats: _ImportStats = Field(default_factory=_ImportStats)
    evidence: int | None = None
    created_at: datetime


class _Client(_Record):
    name: str = Field(min_length=1, max_length=NAME)
    industry: str = ""
    contact_name: str = ""
    contact_email: str = ""
    notes: str = ""


class _Engagement(_Record):
    name: str = Field(min_length=1, max_length=NAME)
    code: EngagementCode  # it names report and CSV downloads
    type: EngagementType
    status: EngagementStatus
    start_date: date | None = None
    end_date: date | None = None
    description: str = ""
    rules_of_engagement: str = ""
    executive_summary: str = ""

    @model_validator(mode="after")
    def _dates(self) -> "_Engagement":
        if self.start_date and self.end_date and self.end_date < self.start_date:
            raise ValueError("end_date is before start_date")
        return self


class _Scope(_Record):
    kind: ScopeKind
    value: str = Field(min_length=1, max_length=512 + 1)  # the API's 512, plus the "/" a URL can gain
    rule: ScopeRule = "include"
    notes: str = ""

    @model_validator(mode="after")
    def _normalize(self) -> "_Scope":
        """As in the API: the value must suit its kind (scope matching relies on that)."""
        try:
            self.value = normalize_scope_value(self.kind, self.value)
        except ValueError as exc:
            raise ValueError(f"invalid {self.kind} scope value: {exc}") from None
        return self


def _show(value: object) -> str:
    text = repr(value) if isinstance(value, str) else str(value)
    return text if len(text) <= 80 else text[:77] + "..."


def _unique(what: str, values: Iterable[Hashable]) -> set:
    seen: set = set()
    for v in values:
        if v in seen:
            raise ValueError(f"{what} {_show(v)} appears more than once")
        seen.add(v)
    return seen


def _resolve(owner: str, what: str, ref: int | None, ids: set[int]) -> None:
    if ref is not None and ref not in ids:
        raise ValueError(f"{owner} refers to {what} {ref}, which the file does not contain")


class Manifest(_Record):
    format: Literal["offsechub-engagement"]
    version: Literal[1]
    created_at: datetime
    app_version: str = Field(max_length=32)
    client: _Client
    engagement: _Engagement
    scope: list[_Scope] = _items()
    targets: list[_Target] = _items()
    findings: list[_Finding] = _items()
    test_cases: list[_TestCase] = _items()
    oplog: list[_Oplog] = _items()
    evidence: list[_Evidence] = _items()
    imports: list[_Import] = _items()

    @model_validator(mode="after")
    def _links(self) -> "Manifest":
        """Ids are unique per list, every link resolves, and the vault's unique keys hold."""
        targets = _unique("target id", (t.id for t in self.targets))
        findings = _unique("finding id", (f.id for f in self.findings))
        tests = _unique("test case id", (tc.id for tc in self.test_cases))
        evidence = _unique("evidence id", (ev.id for ev in self.evidence))
        _unique("target value", (t.value for t in self.targets))
        _unique("finding number", (f.number for f in self.findings))
        for t in self.targets:
            _unique(f"on target {t.id}, service", (f"{s.port}/{s.protocol}" for s in t.services))
        for f in self.findings:
            _unique(f"in finding {f.id}, target", f.targets)
            for ref in f.targets:
                _resolve(f"finding {f.id}", "target", ref, targets)
        for tc in self.test_cases:
            _resolve(f"test case {tc.id}", "target", tc.target, targets)
            _resolve(f"test case {tc.id}", "finding", tc.finding, findings)
        for ev in self.evidence:
            _resolve(f"evidence {ev.id}", "finding", ev.finding, findings)
            _resolve(f"evidence {ev.id}", "target", ev.target, targets)
            _resolve(f"evidence {ev.id}", "test case", ev.test_case, tests)
        for n, imp in enumerate(self.imports):
            _resolve(f"import {n}", "evidence", imp.evidence, evidence)
        return self


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


def _problem(exc: ValidationError) -> str:
    """The first validation error, readably: where it is and what is wrong."""
    first = exc.errors(include_url=False)[0]
    where = ".".join(str(part) for part in first["loc"])
    what = first["msg"].removeprefix("Value error, ")
    more = exc.error_count() - 1
    return (f"{where}: {what}" if where else what) + (f" (and {more} more problem(s))" if more else "")


def read_handoff(vault: OpenVault, src: BinaryIO, passphrase: str
                 ) -> tuple[Manifest, list[storage.StoredBlob]]:
    """Decrypt and validate a hand-off file, storing its evidence as new vault blobs.

    Returns the manifest and the new blobs, one per evidence entry in manifest
    order. On any error every blob written so far is deleted and the error
    (HandoffError for anything wrong with the file) is raised.
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
    written: list[storage.StoredBlob] = []  # every blob committed so far, deleted again on failure
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
            raise HandoffError(f"the file's contents are not valid: {_problem(exc)}") from None
        for ev in manifest.evidence:
            writer = vault.open_blob_writer(ev.size)
            try:
                sha = hashlib.sha256()
                for piece in reader.stream(ev.size):
                    sha.update(piece)
                    writer.write(piece)
                if sha.hexdigest() != ev.sha256:
                    raise HandoffError(f"evidence {ev.filename} does not match its fingerprint")
                written.append(storage.StoredBlob(*writer.commit()))
            finally:
                writer.abort()  # no-op after commit
        if not reader.at_end():
            raise HandoffError("the file is damaged")
        return manifest, written
    except CryptoError:
        storage.delete_blobs(vault, [b.blob_id for b in written])
        raise HandoffError("the passphrase is wrong or the file is damaged") from None
    except BaseException:
        storage.delete_blobs(vault, [b.blob_id for b in written])
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


def apply_manifest(db: Session, m: Manifest, blobs: list[storage.StoredBlob]) -> Engagement:
    """Create the engagement (and its client if new) from a validated manifest. Flushes, no commit.

    ``blobs`` are the evidence files' new blobs in manifest order, as read_handoff
    returns them. Validation guarantees unique ids and links that resolve. On an
    error the caller rolls back and deletes the blobs.
    """
    if len(blobs) != len(m.evidence):
        raise HandoffError("the file's evidence does not match its manifest")
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

    def new_id(rows: dict, old: int | None) -> int | None:
        return None if old is None else rows[old].id

    targets: dict[int, Target] = {}
    for t in m.targets:
        target = Target(engagement_id=eng.id, **t.model_dump(exclude={"id", "services"}),
                        services=[Service(**s.model_dump()) for s in t.services])
        db.add(target)
        targets[t.id] = target
    db.flush()

    findings: dict[int, Finding] = {}
    for f in m.findings:
        finding = Finding(engagement_id=eng.id, **f.model_dump(exclude={"id", "targets", "retests"}),
                          targets=[targets[i] for i in f.targets],
                          retests=[FindingRetest(**r.model_dump()) for r in f.retests])
        db.add(finding)
        findings[f.id] = finding
    db.flush()

    tests: dict[int, TestCase] = {}
    for tc in m.test_cases:
        row = TestCase(engagement_id=eng.id, **tc.model_dump(exclude={"id", "target", "finding"}),
                       target_id=new_id(targets, tc.target), finding_id=new_id(findings, tc.finding))
        db.add(row)
        tests[tc.id] = row
    for o in m.oplog:
        db.add(OperatorLogEntry(engagement_id=eng.id, **o.model_dump()))
    db.flush()

    evidence: dict[int, Evidence] = {}
    for ev, blob in zip(m.evidence, blobs, strict=True):
        row = storage.add_evidence(
            db, blob, engagement_id=eng.id, filename=ev.filename, content_type=ev.content_type,
            description=ev.description, finding_id=new_id(findings, ev.finding),
            target_id=new_id(targets, ev.target), test_case_id=new_id(tests, ev.test_case))
        row.created_at = ev.created_at
        evidence[ev.id] = row
    for imp in m.imports:
        db.add(ReconImport(engagement_id=eng.id, tool=imp.tool, filename=imp.filename,
                           stats=imp.stats.model_dump(), evidence_id=new_id(evidence, imp.evidence),
                           created_at=imp.created_at))
    db.flush()
    audit.record(db, action="import", entity_type="engagement", entity_id=eng.id, engagement_id=eng.id,
                 summary=f"Imported {eng.code} from a hand-off file ({len(m.findings)} findings, "
                         f"{len(m.evidence)} evidence files)")
    return eng
