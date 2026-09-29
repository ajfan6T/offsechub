"""Vault lifecycle, tamper handling, rollback detection, locking and concurrency."""

import json
import os
import shutil
from pathlib import Path
import sqlite3
import threading
import time

import pytest

from app.bootstrap import make_unlock_hook
from app.models import Client
from app.vault import manager as mgr_mod
from app.vault.appconfig import AppConfig
from app.vault.fslock import VaultInUse
from app.vault.manager import VaultError, VaultLocked, VaultManager, WrongSecret

PW = "correct horse battery staple"


@pytest.fixture
def mgr(tmp_path):
    m = VaultManager(AppConfig(tmp_path / "cfg"))
    m.on_unlock(make_unlock_hook(m))
    yield m
    m.shutdown()


@pytest.fixture
def vault_path(mgr, tmp_path):
    mgr.create(tmp_path / "acme", PW)
    return mgr.require().path


def add_client(mgr, name):
    with mgr.require().session() as s:
        s.add(Client(name=name))
        s.commit()


def clients(mgr):
    with mgr.require().session() as s:
        return sorted(c.name for c in s.query(Client))


def test_create_appends_suffix_and_refuses_non_empty(mgr, tmp_path):
    mgr.create(tmp_path / "one", PW)
    assert mgr.require().path.name == "one.ohvault"
    (tmp_path / "busy.ohvault").mkdir()
    (tmp_path / "busy.ohvault" / "file").write_text("x")
    with pytest.raises(VaultError):
        mgr.create(tmp_path / "busy", PW)
    with pytest.raises(VaultError):
        mgr.create(tmp_path / "short", "too short")


def test_nothing_readable_on_disk(mgr, vault_path):
    add_client(mgr, "ACME Very Secret Client")
    v = mgr.require()
    bid, key, sha, size = v.write_blob(b"TOP-SECRET-EVIDENCE" * 500)
    mgr.lock()
    for f in vault_path.rglob("*"):
        if f.is_file():
            data = f.read_bytes()
            assert b"Very Secret" not in data and b"TOP-SECRET" not in data, f


def test_lock_unlock_roundtrip_and_wrong_password(mgr, vault_path):
    add_client(mgr, "ACME")
    mgr.lock()
    assert mgr.state == "locked"
    with pytest.raises(VaultLocked):
        mgr.require()
    with pytest.raises(WrongSecret):
        mgr.unlock(vault_path, password="not the password")
    mgr.unlock(vault_path, password=PW)
    assert clients(mgr) == ["ACME"]


def test_recovery_unlock_forces_reset_and_rotates_key(mgr, tmp_path):
    recovery = mgr.create(tmp_path / "r", PW).key
    path = mgr.require().path
    mgr.lock()
    mgr.unlock(path, recovery_key=recovery)
    v = mgr.require()
    assert mgr.status()["must_set_password"] is True
    new_recovery = v.reset_password(recovery, "a brand new passphrase").key
    assert mgr.status()["must_set_password"] is False
    mgr.lock()
    with pytest.raises(WrongSecret):
        mgr.unlock(path, recovery_key=recovery)  # the exposed key is revoked
    with pytest.raises(WrongSecret):
        mgr.unlock(path, password=PW)
    mgr.unlock(path, recovery_key=new_recovery)


def test_recovery_key_typo_is_reported_as_such(mgr, tmp_path):
    recovery = mgr.create(tmp_path / "t", PW).key
    path = mgr.require().path
    mgr.lock()
    typo = recovery[:-1] + ("Z" if recovery[-1] != "Z" else "Y")
    with pytest.raises(WrongSecret, match="typo"):
        mgr.unlock(path, recovery_key=typo)


def test_blob_roundtrip_limits_and_integrity(mgr, vault_path):
    v = mgr.require()
    data = os.urandom(200_000)
    bid, key, sha, size = v.write_blob(iter([data[:70_000], data[70_000:]]))
    assert v.read_blob_bytes(bid, key, sha256=sha, size=size) == data
    with pytest.raises(mgr_mod.BlobIntegrityError):
        v.read_blob_bytes(bid, key, sha256="0" * 64, size=size)
    with pytest.raises(ValueError):
        v.write_blob(iter([b"x" * 2000]), limit=1000)
    assert len(v.blob_ids_on_disk()) == 1  # the rejected upload left nothing behind
    with pytest.raises(ValueError):
        v.read_blob("../../etc/passwd", key)


def test_password_change_and_header_rollback_is_repaired(mgr, vault_path):
    v = mgr.require()
    old_header = (vault_path / "vault.json").read_text()
    v.change_password(PW, "second passphrase here")
    mgr.lock()
    # Attacker restores the old header (whose password they know) on both copies.
    (vault_path / "vault.json").write_text(old_header)
    (vault_path / "vault.json.mirror").write_text(old_header)
    mgr.unlock(vault_path, password=PW)
    assert any("rollback" in w for w in mgr.status()["warnings"])
    mgr.lock()
    with pytest.raises(WrongSecret):
        mgr.unlock(vault_path, password=PW)  # the authentic header was restored
    mgr.unlock(vault_path, password="second passphrase here")


def test_tampered_or_deleted_keyslot_is_detected_and_restored(mgr, vault_path):
    mgr.lock()
    header = json.loads((vault_path / "vault.json").read_text())
    header["keyslots"] = [s for s in header["keyslots"] if s["type"] != "recovery"]
    (vault_path / "vault.json").write_text(json.dumps(header))
    mgr.unlock(vault_path, password=PW)
    assert any("integrity" in w for w in mgr.status()["warnings"])
    restored = json.loads((vault_path / "vault.json").read_text())
    assert {s["type"] for s in restored["keyslots"]} == {"password", "recovery"}


def test_damaged_primary_header_falls_back_to_mirror(mgr, vault_path):
    mgr.lock()
    (vault_path / "vault.json").write_text("{ not json")
    mgr.unlock(vault_path, password=PW)
    assert json.loads((vault_path / "vault.json").read_text())["format"] == "offsechub-vault"


def test_tampered_database_is_quarantined_and_backup_kept(mgr, vault_path):
    add_client(mgr, "c1")
    mgr.lock()
    mgr.unlock(vault_path, password=PW)
    add_client(mgr, "c2")
    mgr.lock()
    blob = bytearray((vault_path / "db.enc").read_bytes())
    blob[200] ^= 1
    (vault_path / "db.enc").write_bytes(blob)
    mgr.unlock(vault_path, password=PW)
    status = mgr.status()
    assert any("backup" in w for w in status["warnings"])
    assert clients(mgr) == ["c1"]
    assert list(vault_path.glob("db.enc.corrupt-*"))
    add_client(mgr, "c3")
    mgr.lock()
    # The quarantined file never displaced the good backup.
    assert (vault_path / "db.enc").exists() and (vault_path / "db.enc.bak").exists()


def test_interrupted_save_is_recovered_from_tmp(mgr, vault_path):
    add_client(mgr, "before")
    v = mgr.require()
    v.save()
    # Simulate a crash after the tmp was written but before it was promoted.
    with v.session() as s:
        s.add(Client(name="in-flight"))
        s.commit()
    with v.db_lock:
        data = v._conn.serialize()
    from app.vault import crypto

    gen = v.generation + 1
    (vault_path / f"db.enc.{gen}.tmp").write_bytes(crypto.encrypt_snapshot(v._mk, v.vault_id, gen, data))
    v._saved_seq = v._commit_seq  # pretend nothing is pending
    v._saved_marker = v._change_marker()
    mgr.lock()
    assert (vault_path / f"db.enc.{gen}.tmp").exists()
    mgr.unlock(vault_path, password=PW)
    assert "in-flight" in clients(mgr)
    assert mgr.status()["notices"] and not mgr.status()["warnings"]


def test_snapshot_rollback_detected_by_high_water_mark(mgr, vault_path):
    add_client(mgr, "a")
    mgr.lock()
    shutil.copy(vault_path / "db.enc", vault_path.parent / "old.enc")
    mgr.unlock(vault_path, password=PW)
    add_client(mgr, "b")
    mgr.lock()
    shutil.copy(vault_path.parent / "old.enc", vault_path / "db.enc")
    (vault_path / "db.enc.bak").unlink()
    mgr.unlock(vault_path, password=PW)
    assert any("older than the last version" in w for w in mgr.status()["warnings"])


def test_rekey_revokes_old_header_and_keeps_data(mgr, vault_path):
    add_client(mgr, "kept")
    v = mgr.require()
    bid, key, sha, size = v.write_blob(b"evidence")
    old_header = (vault_path / "vault.json").read_text()
    v.rekey(PW)
    assert not (vault_path / "db.enc.bak").exists()
    mgr.lock()
    mgr.unlock(vault_path, password=PW)
    assert clients(mgr) == ["kept"]
    assert mgr.require().read_blob_bytes(bid, key, sha256=sha, size=size) == b"evidence"
    mgr.lock()
    # An attacker holding the pre-rekey header and password gets nothing current.
    (vault_path / "vault.json").write_text(old_header)
    (vault_path / "vault.json.mirror").write_text(old_header)
    with pytest.raises(VaultError):
        mgr.unlock(vault_path, password=PW)


def test_second_instance_cannot_open_the_same_vault(mgr, vault_path, tmp_path):
    other = VaultManager(AppConfig(tmp_path / "cfg2"))
    try:
        with pytest.raises(VaultInUse):
            other.unlock(vault_path, password=PW)
    finally:
        other.shutdown()


def test_connection_pragmas_keep_plaintext_off_disk(mgr, vault_path):
    conn: sqlite3.Connection = mgr.require()._conn
    assert conn.execute("PRAGMA temp_store").fetchone()[0] == 2  # MEMORY
    assert conn.execute("PRAGMA secure_delete").fetchone()[0] == 1


def test_concurrent_sessions_are_serialised(mgr, vault_path):
    errors = []

    def worker(n):
        try:
            for i in range(20):
                add_client(mgr, f"w{n}-{i}")
        except Exception as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(clients(mgr)) == 160
    mgr.lock()
    mgr.unlock(vault_path, password=PW)
    assert len(clients(mgr)) == 160


def test_saves_are_coalesced(mgr, vault_path):
    v = mgr.require()
    start = v.generation
    for i in range(50):
        add_client(mgr, f"c{i}")
    time.sleep(mgr_mod.SAVE_DEBOUNCE_S * 5)
    assert not v.dirty
    assert v.generation - start < 10


def test_auto_lock(mgr, vault_path, monkeypatch):
    mgr.auto_lock_minutes = 1
    mgr.last_activity = time.monotonic() - 61
    deadline = time.time() + 10
    while mgr.state == "unlocked" and time.time() < deadline:
        time.sleep(0.2)
    assert mgr.state == "locked" and mgr.status()["lock_reason"] == "idle"


def test_session_after_lock_raises_locked(mgr, vault_path):
    v = mgr.require()
    mgr.lock()
    with pytest.raises(VaultLocked):
        with v.session():
            pass


def test_incremental_blob_writer(mgr, vault_path):
    v = mgr.require()
    w = v.open_blob_writer(limit=10_000_000)
    data = os.urandom(300_000)
    for i in range(0, len(data), 4096):
        w.write(data[i : i + 4096])
    bid, key, sha, size = w.commit()
    assert v.read_blob_bytes(bid, key, sha256=sha, size=size) == data
    w2 = v.open_blob_writer(limit=100)
    with pytest.raises(ValueError):
        w2.write(b"x" * 101)
    assert not list((vault_path / "blobs").rglob(".*.tmp"))


# ------------------------------------------------------------ durability


def test_failed_flush_on_lock_keeps_the_data(mgr, vault_path, monkeypatch):
    """Disk full while auto-locking: nothing acknowledged may be lost."""
    add_client(mgr, "saved")
    v = mgr.require()
    v.save()
    real = mgr_mod.write_snapshot_file

    def disk_full(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(mgr_mod, "write_snapshot_file", disk_full)
    with v.session() as s:
        s.add(Client(name="only-in-memory"))
        s.commit()
    mgr.lock(reason="idle")
    assert mgr.state == "locked"
    assert mgr.status()["save_error"]  # the UI can tell the user
    monkeypatch.setattr(mgr_mod, "write_snapshot_file", real)
    mgr.unlock(vault_path, password=PW)  # retries the write, or loads from memory
    assert "only-in-memory" in clients(mgr)
    mgr.lock()
    mgr.unlock(vault_path, password=PW)
    assert "only-in-memory" in clients(mgr)  # and it really reached the disk


def test_failed_flush_on_exit_leaves_an_encrypted_rescue_copy(mgr, vault_path, monkeypatch):
    add_client(mgr, "late change")

    def disk_full(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(mgr_mod, "write_snapshot_file", disk_full)
    mgr.shutdown()
    rescue = list((mgr.config.dir / "unsaved").glob("*.db.enc"))
    assert rescue and b"late change" not in rescue[0].read_bytes()


def test_recovered_tmp_survives_a_second_interrupted_save(mgr, vault_path, monkeypatch):
    """The recovered generation must never be truncated before it is promoted."""
    from app.vault import crypto

    add_client(mgr, "base")
    v = mgr.require()
    v.save()
    with v.session() as s:
        s.add(Client(name="recovered"))
        s.commit()
    with v.db_lock:
        data = v._conn.serialize()
    gen = v.generation + 1
    (vault_path / f"db.enc.{gen}.tmp").write_bytes(crypto.encrypt_snapshot(v._mk, v.vault_id, gen, data))
    v._saved_seq, v._saved_marker = v._commit_seq, v._change_marker()
    mgr.lock()
    mgr.unlock(vault_path, password=PW)
    assert "recovered" in clients(mgr)

    # The promoting save itself is interrupted before the final rename...
    def crash(src, dst):
        raise OSError(5, "I/O error")

    monkeypatch.setattr(mgr_mod.durable, "replace", crash)
    try:
        mgr.require().save()
    except OSError:
        pass
    monkeypatch.undo()
    mgr.current.close()  # simulate the process dying
    mgr.current = None
    mgr.locked_path = vault_path
    mgr.unlock(vault_path, password=PW)
    assert "recovered" in clients(mgr)


def test_blob_deletion_waits_until_no_snapshot_references_it(mgr, vault_path):
    v = mgr.require()
    bid, key, sha, size = v.write_blob(b"evidence")
    v.delete_blob(bid)
    assert bid in v.blob_ids_on_disk()  # still referenced by db.enc/.bak
    deadline = time.time() + 5
    while bid in v.blob_ids_on_disk() and time.time() < deadline:
        time.sleep(0.05)
    assert bid not in v.blob_ids_on_disk()
    assert v.generation >= 2


def test_recovery_kit_restores_a_vault_whose_headers_are_all_lost(mgr, tmp_path):
    info = mgr.create(tmp_path / "kit", PW)
    path = mgr.require().path
    add_client(mgr, "survivor")
    mgr.lock()
    (path / "vault.json").unlink()
    (path / "vault.json.mirror").unlink()
    with pytest.raises(VaultError, match="recovery kit"):
        mgr.unlock(path, recovery_key=info.key)
    mgr.unlock(path, recovery_key=info.key, recovery_kit=info.kit)
    assert clients(mgr) == ["survivor"]
    assert (path / "vault.json").exists() and (path / "vault.json.mirror").exists()
    mgr.require().reset_password(info.key, "a new password here")
    mgr.lock()
    mgr.unlock(path, password="a new password here")


def test_kit_from_another_vault_is_refused(mgr, tmp_path):
    other = mgr.create(tmp_path / "other", PW)
    info = mgr.create(tmp_path / "mine", PW)
    path = mgr.require().path
    mgr.lock()
    with pytest.raises(VaultError, match="different vault"):
        mgr.unlock(path, recovery_key=info.key, recovery_kit=other.kit)


def test_backup_is_consistent_and_opens_with_the_same_password(mgr, vault_path, tmp_path):
    add_client(mgr, "in backup")
    v = mgr.require()
    v.write_blob(b"screenshot")
    result = v.export_backup(tmp_path / "copy")
    assert result["evidence_files"] == 1
    mgr.lock()
    mgr.unlock(Path(result["path"]), password=PW)
    assert clients(mgr) == ["in backup"]


def test_verify_reports_missing_and_corrupt_evidence(mgr, vault_path):
    from app.models import Engagement, Evidence

    v = mgr.require()
    good = v.write_blob(b"good file")
    bad = v.write_blob(b"will be damaged")
    with v.session() as s:
        from app.models import Client as C

        c = C(name="x")
        s.add(c)
        s.flush()
        e = Engagement(client_id=c.id, name="e", code="E1", type="api")
        s.add(e)
        s.flush()
        for name, (bid, key, sha, size) in (("good.txt", good), ("bad.txt", bad)):
            s.add(Evidence(engagement_id=e.id, filename=name, content_type="text/plain", size=size,
                           sha256=sha, storage_key=bid, blob_key=key))
        s.commit()
    p = v._blob_path(bad[0])
    data = bytearray(p.read_bytes())
    data[-1] ^= 1
    p.write_bytes(data)
    report = v.verify()
    assert report["evidence"] == 2 and report["verified"] == 1 and report["corrupt"] == ["bad.txt"]


def test_generation_is_never_reused_after_a_fallback(mgr, vault_path):
    add_client(mgr, "a")
    mgr.lock()
    mgr.unlock(vault_path, password=PW)
    add_client(mgr, "b")
    mgr.lock()
    bad = bytearray((vault_path / "db.enc").read_bytes())
    corrupt_gen = int.from_bytes(bad[21:29], "big")
    bad[200] ^= 1
    (vault_path / "db.enc").write_bytes(bad)
    mgr.unlock(vault_path, password=PW)
    add_client(mgr, "c")
    mgr.require().save()
    assert mgr.require().generation > corrupt_gen


def test_newer_snapshot_version_is_refused_not_quarantined(mgr, vault_path):
    mgr.lock()
    data = bytearray((vault_path / "db.enc").read_bytes())
    data[4] = 2  # a future format version
    (vault_path / "db.enc").write_bytes(data)
    with pytest.raises(mgr_mod.NewerVersion):
        mgr.unlock(vault_path, password=PW)
    assert (vault_path / "db.enc").read_bytes() == bytes(data)  # untouched
    assert not list(vault_path.glob("db.enc.corrupt-*"))


def test_newer_header_version_is_refused(mgr, vault_path):
    mgr.lock()
    for name in ("vault.json", "vault.json.mirror"):
        h = json.loads((vault_path / name).read_text())
        h["version"] = 2
        (vault_path / name).write_text(json.dumps(h))
    with pytest.raises(mgr_mod.NewerVersion):
        mgr.unlock(vault_path, password=PW)


def test_lock_is_quiescent(mgr, vault_path):
    """A request queued behind the DB lock during lock() gets 423, never a lost write."""
    v = mgr.require()
    results = []
    entered = threading.Event()
    release = threading.Event()

    def slow_request():
        with v.session() as s:  # holds the DB lock, like a long endpoint
            s.add(Client(name="in-flight"))
            s.commit()
            entered.set()
            release.wait(5)

    def queued_request():
        entered.wait(5)
        try:
            with v.session() as s:
                s.add(Client(name="too-late"))
                s.commit()
            results.append("committed")
        except VaultLocked:
            results.append("locked")

    t1 = threading.Thread(target=slow_request)
    t2 = threading.Thread(target=queued_request)
    t1.start()
    t2.start()
    entered.wait(5)
    locker = threading.Thread(target=mgr.lock)
    locker.start()
    time.sleep(0.2)
    release.set()
    for t in (t1, t2, locker):
        t.join(10)
    mgr.unlock(vault_path, password=PW)
    names = clients(mgr)
    assert "in-flight" in names  # committed before the seal: persisted
    if results == ["committed"]:  # won the race before the seal: must then be persisted too
        assert "too-late" in names
    else:
        assert results == ["locked"] and "too-late" not in names


def test_database_size_is_capped(mgr, vault_path):
    conn = mgr.require()._conn
    pages = conn.execute("PRAGMA max_page_count").fetchone()[0]
    page_size = conn.execute("PRAGMA page_size").fetchone()[0]
    assert pages * page_size == mgr_mod.MAX_DB_BYTES


def test_process_hardening_applies():
    from app.vault.hardening import harden_process

    applied = harden_process()
    assert "core dumps disabled" in applied
