"""Property-based fuzzing of every parser that sees untrusted input.

Scanner output is attacker-influenced (banners, hostnames, HTTP bodies) and
vault files may have been tampered with, so each of these must fail only
with its documented error type, never crash or hang.
"""

import io
import json

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

from app.services.importers.parsers import ParseError, parse_list, parse_nmap_xml, parse_nuclei  # noqa: E402
from app.services.scope import ScopeMatcher, normalize_scope_value, parse_identifier  # noqa: E402
from app.vault import crypto  # noqa: E402
from app.vault.header import VaultFormatError, VaultHeader  # noqa: E402

FUZZ = settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])


class Rule:
    def __init__(self, id, kind, value, rule="include"):
        self.id, self.kind, self.rule, self.value = id, kind, rule, normalize_scope_value(kind, value)


MATCHER = ScopeMatcher([Rule(1, "cidr", "10.0.0.0/8"), Rule(2, "wildcard", "*.example.com"),
                        Rule(3, "url", "https://app.example.com/api"), Rule(4, "ip", "10.0.0.5", "exclude")])


@FUZZ
@given(st.text(max_size=300))
def test_scope_matching_never_crashes(value):
    parse_identifier(value)
    assert MATCHER.check(value).status in {"in_scope", "out_of_scope", "excluded"}


@FUZZ
@given(st.sampled_from(["ip", "cidr", "range", "domain", "wildcard", "url", "other"]), st.text(max_size=200))
def test_scope_normalisation_only_raises_value_error(kind, value):
    try:
        normalize_scope_value(kind, value)
    except ValueError:
        pass


@FUZZ
@given(st.binary(max_size=4000))
def test_list_parser(data):
    parse_list(data)  # never raises: bad lines become errors


@FUZZ
@given(st.binary(max_size=4000))
def test_nuclei_parser(data):
    try:
        parse_nuclei(data)
    except ParseError:
        pass


json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=40),
    lambda inner: st.lists(inner, max_size=5) | st.dictionaries(st.text(max_size=15), inner, max_size=6),
    max_leaves=30,
)


@FUZZ
@given(st.lists(st.dictionaries(st.sampled_from(["template-id", "info", "host", "matched-at", "ip",
                                                 "curl-command", "extracted-results"]), json_values),
                max_size=5))
def test_nuclei_parser_structured(records):
    data = "\n".join(json.dumps(r) for r in records).encode()
    try:
        parse_nuclei(data)
    except ParseError:
        pass


xml_fragments = st.lists(st.sampled_from([
    "<nmaprun>", "</nmaprun>", "<host>", "</host>", '<status state="up"/>', '<status state="down"/>',
    '<address addr="10.0.0.1" addrtype="ipv4"/>', '<address addrtype="ipv6"/>', "<ports>", "</ports>",
    '<port protocol="tcp" portid="80">', '<port portid="x">', "</port>", '<state state="open"/>',
    '<service name="http" product="nginx"/>', "<hostnames>", '<hostname name="a.example.com"/>', "</hostnames>",
    '<os><osmatch name="Linux" accuracy="9x"/></os>', "&amp;", "<!-- c -->", "junk", "<", ">",
]), max_size=40)


@FUZZ
@given(xml_fragments)
def test_nmap_parser(fragments):
    try:
        parse_nmap_xml("".join(fragments).encode())
    except ParseError:
        pass


@FUZZ
@given(st.text(max_size=120))
def test_recovery_key_decoding(text):
    try:
        crypto.decode_recovery_key(text)
    except ValueError:
        pass


@FUZZ
@given(json_values)
def test_vault_header_parsing(raw):
    try:
        VaultHeader.from_json(raw)
    except VaultFormatError:
        pass


@FUZZ
@given(st.binary(max_size=3000))
def test_blob_and_snapshot_decoders_reject_garbage(data):
    with pytest.raises(crypto.CryptoError):
        b"".join(crypto.decrypt_blob(b"\x00" * 32, b"\x00" * 16, io.BytesIO(data)))
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_snapshot(bytearray(32), b"\x00" * 16, data)


@FUZZ
@given(st.binary(min_size=1, max_size=200_000), st.integers(0, 199_999), st.integers(1, 255))
def test_any_single_byte_flip_in_a_blob_is_detected(data, pos, flip):
    out = io.BytesIO()
    enc = crypto.BlobEncryptor(b"\x07" * 32, b"\x01" * 16, out)
    enc.write(data)
    enc.finish()
    ct = bytearray(out.getvalue())
    ct[pos % len(ct)] ^= flip
    with pytest.raises(crypto.CryptoError):
        b"".join(crypto.decrypt_blob(b"\x07" * 32, b"\x01" * 16, io.BytesIO(bytes(ct))))
