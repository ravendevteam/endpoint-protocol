from __future__ import annotations

import base64
import hashlib

import pytest

import endpoint.crypto as crypto
from endpoint.crypto import display_fingerprint
from endpoint.contact import validate_endpoint_fingerprint
from endpoint.errors import EndpointError
from endpoint.protocol import validate_fingerprint


def test_rfc9580_v4_fingerprint_reference_vector() -> None:
	body = bytes.fromhex("040102030401000801000305")
	preimage = b"\x99" + len(body).to_bytes(2, "big") + body
	assert preimage.hex() == "99000c040102030401000801000305"
	assert hashlib.sha1(preimage).hexdigest() == "ccf6fd1373a2a3762c4b84208eef4230ef4daf16"


def test_rfc9580_v6_fingerprint_reference_vector() -> None:
	body = bytes.fromhex("060506070812aabbcc")
	preimage = b"\x9b" + len(body).to_bytes(4, "big") + body
	assert preimage.hex() == "9b00000009060506070812aabbcc"
	assert hashlib.sha256(preimage).hexdigest() == "8ca2f57264942767d8a2087d2aa4f104488be410b84a7cae868829d132d7277e"


@pytest.mark.parametrize("digest", (bytes(range(20)), bytes(range(32))))
def test_endpoint_fingerprint_encodes_native_digest_without_an_extra_hash(monkeypatch: pytest.MonkeyPatch, digest: bytes) -> None:
	monkeypatch.setattr(crypto, "openpgp_fingerprint_bytes", lambda _public_key: digest)
	expected = "ep1:" + base64.b32encode(digest).decode("ascii").rstrip("=").lower()
	assert crypto.endpoint_fingerprint("unused") == expected
	assert len(expected.removeprefix("ep1:")) in {32, 52}


@pytest.mark.parametrize("suffix_length", (32, 52))
def test_fingerprint_validators_accept_native_v4_and_v6_lengths(suffix_length: int) -> None:
	fingerprint = "ep1:" + ("a" * suffix_length)
	validate_fingerprint(fingerprint)
	assert validate_endpoint_fingerprint(fingerprint) == fingerprint


@pytest.mark.parametrize(
	"fingerprint",
	(
		"ep1:" + ("a" * 31),
		"ep1:" + ("a" * 33),
		"ep1:" + ("a" * 51),
		"ep1:" + ("a" * 53),
		"ep1:" + ("A" * 32),
		"ep1:" + ("a" * 31) + "=",
		"ep1:" + ("a" * 31) + "0",
		"ep1:" + ("a" * 31) + " a",
	),
)
def test_fingerprint_validators_reject_noncanonical_values(fingerprint: str) -> None:
	with pytest.raises(EndpointError):
		validate_fingerprint(fingerprint)
	with pytest.raises(EndpointError):
		validate_endpoint_fingerprint(fingerprint)


@pytest.mark.parametrize("suffix_length", (32, 52))
def test_display_fingerprint_handles_both_native_lengths(suffix_length: int) -> None:
	fingerprint = "ep1:" + ("a" * suffix_length)
	expected = "EP1 " + " ".join("A" * 4 for _ in range(suffix_length // 4))
	assert display_fingerprint(fingerprint) == expected


def test_endpoint_fingerprint_rejects_unsupported_digest_length(monkeypatch: pytest.MonkeyPatch) -> None:
	monkeypatch.setattr(crypto, "openpgp_fingerprint_bytes", lambda _public_key: b"x" * 21)
	with pytest.raises(EndpointError):
		crypto.endpoint_fingerprint("unused")
