"""Vault primitives: recovery keys, KDF bounds, key wrap, snapshots, STREAM blobs."""

import io
import os
import struct

import pytest

from app.vault import crypto as c

MK = bytearray(range(32))
VID = bytes(range(16))


# ------------------------------------------------------------ recovery keys


def test_recovery_key_roundtrip_is_forgiving_about_formatting():
    raw = os.urandom(32)
    text = c.encode_recovery_key(raw)
    assert text.startswith("OHRK-")
    messy = "  " + text.lower().replace("-", " ").replace("0", "o").replace("1", "l") + "\n"
    assert c.decode_recovery_key(messy) == raw


@pytest.mark.parametrize("seed", range(5))
def test_every_single_character_typo_is_detected(seed):
    """Guaranteed by the mod-37 check symbol, not probabilistic."""
    raw = bytes((seed * 37 + i * 11) % 256 for i in range(32))
    body = c.encode_recovery_key(raw).removeprefix("OHRK-").replace("-", "")
    alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ*~$=U"
    for pos in range(len(body)):
        for ch in alphabet:
            if ch == body[pos]:
                continue
            with pytest.raises(ValueError, match="typo|invalid"):
                c.decode_recovery_key(body[:pos] + ch + body[pos + 1 :])


@pytest.mark.parametrize("seed", range(5))
def test_every_adjacent_transposition_is_detected(seed):
    raw = bytes((seed * 53 + i * 7) % 256 for i in range(32))
    body = c.encode_recovery_key(raw).removeprefix("OHRK-").replace("-", "")
    for pos in range(len(body) - 1):
        if body[pos] == body[pos + 1]:
            continue
        swapped = body[:pos] + body[pos + 1] + body[pos] + body[pos + 2 :]
        with pytest.raises(ValueError):
            c.decode_recovery_key(swapped)


@pytest.mark.parametrize("bad", ["", "OHRK-", "OHRK-UUUUU", "OHRK-" + "!" * 55])
def test_malformed_recovery_keys(bad):
    with pytest.raises(ValueError):
        c.decode_recovery_key(bad)


# --------------------------------------------------------------------- KDFs


def test_password_is_nfc_normalised():
    salt = os.urandom(16)
    params = c.Argon2Params(m_kib=19456, t=2, p=1)
    composed = "café-password!"  # é as one code point
    decomposed = "café-password!"  # e + combining accent (macOS style)
    assert c.derive_password_kek(composed, salt, params) == c.derive_password_kek(decomposed, salt, params)


@pytest.mark.parametrize("params", [
    c.Argon2Params(m_kib=1024, t=3, p=4),          # downgrade
    c.Argon2Params(m_kib=2**32 - 1, t=3, p=4),     # memory bomb
    c.Argon2Params(m_kib=65536, t=10_000, p=4),    # time bomb
    c.Argon2Params(m_kib=65536, t=3, p=1000),      # thread bomb
])
def test_untrusted_kdf_parameters_are_bounded_before_use(params):
    with pytest.raises(c.CryptoError):
        c.derive_password_kek("whatever-password", os.urandom(16), params)


# ----------------------------------------------------------------- key wrap


def test_wrap_is_bound_to_its_aad():
    kek = os.urandom(32)
    nonce, wrapped = c.wrap_key(kek, MK, b"slot-a")
    assert c.unwrap_key(kek, nonce, wrapped, b"slot-a") == MK
    with pytest.raises(c.CryptoError):
        c.unwrap_key(kek, nonce, wrapped, b"slot-b")
    with pytest.raises(c.CryptoError):
        c.unwrap_key(os.urandom(32), nonce, wrapped, b"slot-a")


# ---------------------------------------------------------------- snapshots


def test_snapshot_roundtrip_and_fresh_randomness():
    a = c.encrypt_snapshot(MK, VID, 5, b"db bytes")
    b = c.encrypt_snapshot(MK, VID, 5, b"db bytes")
    assert a != b  # fresh salt + nonce per snapshot
    assert c.decrypt_snapshot(MK, VID, a) == (5, b"db bytes")
    assert c.peek_snapshot_generation(a) == 5


@pytest.mark.parametrize("offset", [0, 4, 5, 21, 28, 29, 61, 73, -1])
def test_every_snapshot_header_byte_and_the_body_are_authenticated(offset):
    blob = bytearray(c.encrypt_snapshot(MK, VID, 5, b"db bytes" * 10))
    blob[offset] ^= 0x01
    with pytest.raises(c.CryptoError):
        c.decrypt_snapshot(MK, VID, bytes(blob))


def test_snapshot_from_another_vault_is_rejected():
    blob = c.encrypt_snapshot(MK, VID, 1, b"x")
    with pytest.raises(c.CryptoError):
        c.decrypt_snapshot(MK, bytes(16), blob)


# -------------------------------------------------------------------- blobs


def _encrypt(data: bytes, key=None, bid=VID, step=10_000):
    key = key or os.urandom(32)
    out = io.BytesIO()
    enc = c.BlobEncryptor(key, bid, out)
    for i in range(0, len(data), step):
        enc.write(data[i : i + step])
    sha = enc.finish()
    return key, out.getvalue(), sha


def _decrypt(key, ct, bid=VID):
    return b"".join(c.decrypt_blob(key, bid, io.BytesIO(ct)))


CS = c.CHUNK_SIZE


@pytest.mark.parametrize("size", [0, 1, CS - 1, CS, CS + 1, 2 * CS, 3 * CS + 7])
def test_blob_roundtrip_sizes(size):
    data = os.urandom(size)
    key, ct, sha = _encrypt(data)
    assert _decrypt(key, ct) == data
    import hashlib

    assert sha == hashlib.sha256(data).hexdigest()


def test_exact_multiple_uses_a_full_final_chunk_not_an_empty_one():
    key, ct, _ = _encrypt(os.urandom(2 * CS))
    assert len(ct) == c.BLOB_HEADER_LEN + 2 * (CS + c.TAG_LEN)


def _chunks(ct):
    body = ct[c.BLOB_HEADER_LEN :]
    n = CS + c.TAG_LEN
    return ct[: c.BLOB_HEADER_LEN], [body[i : i + n] for i in range(0, len(body), n)]


def test_header_only_file_is_rejected():
    key, ct, _ = _encrypt(b"")
    with pytest.raises(c.CryptoError):
        _decrypt(key, ct[: c.BLOB_HEADER_LEN])


def test_truncation_at_a_chunk_boundary_is_rejected():
    key, ct, _ = _encrypt(os.urandom(3 * CS + 5))
    header, chunks = _chunks(ct)
    with pytest.raises(c.CryptoError):
        _decrypt(key, header + b"".join(chunks[:2]))


def test_appended_and_swapped_chunks_are_rejected():
    key, ct, _ = _encrypt(os.urandom(3 * CS + 5))
    header, chunks = _chunks(ct)
    with pytest.raises(c.CryptoError):
        _decrypt(key, ct + chunks[0])
    with pytest.raises(c.CryptoError):
        _decrypt(key, header + chunks[1] + chunks[0] + chunks[2] + chunks[3])


def test_forged_empty_final_chunk_after_data_is_rejected():
    key = os.urandom(32)
    header = struct.pack(">4sB16sI", b"OHBL", 1, VID, CS)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aead = AESGCM(key)
    full = aead.encrypt(b"\x00" * 7 + struct.pack(">I", 0) + b"\x00", b"a" * CS, header)
    empty_final = aead.encrypt(b"\x00" * 7 + struct.pack(">I", 1) + b"\x01", b"", header)
    with pytest.raises(c.CryptoError):
        _decrypt(key, header + full + empty_final)


def test_blob_is_bound_to_its_id_and_header():
    key, ct, _ = _encrypt(b"evidence")
    with pytest.raises(c.CryptoError):
        _decrypt(key, ct, bid=bytes(16))
    tampered = bytearray(ct)
    tampered[c.BLOB_HEADER_LEN - 1] ^= 1  # chunk_size field
    with pytest.raises(c.CryptoError):
        _decrypt(key, bytes(tampered))


def test_wrong_key_fails():
    _, ct, _ = _encrypt(b"evidence")
    with pytest.raises(c.CryptoError):
        _decrypt(os.urandom(32), ct)
