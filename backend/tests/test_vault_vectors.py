"""Known-answer vectors for the vault format (docs/VAULT_FORMAT.md, "Test vectors").

These pin the byte-level format so it can be re-implemented independently.
They were cross-checked against independent implementations: Argon2id with
the reference ``argon2`` CLI (phc-winner-argon2), HKDF with ``openssl kdf``,
and the AES-256-GCM keyslot/snapshot vectors with PyCryptodome plus a
hand-written RFC 5869 HKDF.
"""

import hashlib
import io

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.vault import crypto as c
from app.vault import header as h

PASSWORD = "correct horse battery staple"
VAULT_ID = bytes.fromhex("9d1c5b0e2f5a4c0b8f1e3a7d6c2b4e10")
MK = bytearray(range(32, 64))
KDF = {"alg": "argon2id", "v": 19, "len": 32, "salt": "AAECAwQFBgcICQoLDA0ODw==",
       "m_kib": 19456, "t": 2, "p": 1}
WRAP_KEK = bytes.fromhex("818259b6310026a8e0dbac5d2e6927abcfdb07b32258fac4f61b18b80f929085")
WRAPPED = bytes.fromhex(
    "f9b6d829a39b44a1a9dd779c3a29b86131882f753eb192200a4be4763fde041e"
    "5ff11a9418184d6e2e3456aad4e6319a"
)


def test_argon2id_kek():
    kek = c.derive_password_kek(PASSWORD, b"offsechub-salt16", c.Argon2Params(m_kib=19456, t=2, p=1))
    assert bytes(kek).hex() == "528bb0a98a6034439a6889c394d0678cdfd61171bdcdeff1d57a7ceac5b89659"


def test_password_nfc():
    decomposed = "café password!!"
    kek = c.derive_password_kek(decomposed, b"offsechub-salt16", c.Argon2Params(m_kib=19456, t=2, p=1))
    composed = c.derive_password_kek("café password!!", b"offsechub-salt16",
                                     c.Argon2Params(m_kib=19456, t=2, p=1))
    assert kek == composed


def test_recovery_kek_hkdf():
    kek = c.hkdf(bytes(range(32)), b"\x11" * 16, b"offsechub/v1/kek-recovery")
    assert bytes(kek).hex() == "6235fde4c0fabb12070d4b81693c46919a8212ac98be137a7ff0b479965ef315"


def test_recovery_key_text():
    text = c.encode_recovery_key(bytes(range(32)))
    assert text == "OHRK-000G4-0R40M-30E20-9185G-R38E1-W8124-GK2GA-HC5RR-34D1P-70X3R-FPY6R-V"
    assert c.decode_recovery_key(text) == bytes(range(32))


def test_keyslot_aad_and_wrap():
    aad = h._slot_aad(VAULT_ID, "password", KDF)
    assert aad == (
        b"offsechub-vault/v1/keyslot|" + VAULT_ID + b"|password|"
        b'{"alg":"argon2id","len":32,"m_kib":19456,"p":1,"salt":"AAECAwQFBgcICQoLDA0ODw==","t":2,"v":19}'
    )
    assert AESGCM(WRAP_KEK).encrypt(b"\x01" * 12, bytes(MK), aad) == WRAPPED
    assert c.unwrap_key(WRAP_KEK, b"\x01" * 12, WRAPPED, aad) == MK


def test_snapshot(monkeypatch):
    monkeypatch.setattr(c, "random_bytes", lambda n: b"\x22" * 32)  # the per-snapshot salt
    snap = c.encrypt_snapshot(MK, VAULT_ID, 1, b"OffsecHub")
    assert snap.hex() == (
        "4f48444201" "9d1c5b0e2f5a4c0b8f1e3a7d6c2b4e10" "0000000000000001" + "22" * 32 + "00010000"
        + "b2303f5141f26e8bcbab60018b1be710bf9508c2affeb7d97d"
    )
    assert c.decrypt_snapshot(MK, VAULT_ID, snap) == (1, b"OffsecHub")


def test_blob_stream():
    out = io.BytesIO()
    enc = c.BlobEncryptor(b"\x44" * 32, b"\x55" * 16, out)
    enc.write(bytes(i % 251 for i in range(70000)))
    plain_sha = enc.finish()
    ct = out.getvalue()
    assert len(ct) == 25 + (65536 + 16) + (70000 - 65536 + 16)
    assert hashlib.sha256(ct).hexdigest() == "88ab0f447fe714dc311b61693e4efdef9a3e7df96eccfa4f534e16328dc59acd"
    assert plain_sha == "9dc177c2fde29dea8e7c29f7ddf147b7c449c99d049c62f3aac0a5933ecf76a3"


def test_header_mac():
    header = h.VaultHeader(vault_id=VAULT_ID, revision=1,
                           keyslots=[h.Keyslot("password", KDF, b"\x01" * 12, WRAPPED)])
    body = c.canonical_json(header.body())
    assert body.startswith(b'{"format":"offsechub-vault","keyslots":[{"kdf":{"alg":"argon2id"')
    assert c.header_mac(MK, body) == "9a74c31d844d9bf1db238bca4eb26d24862e9beb04b30b28954fb1f2dca97601"
