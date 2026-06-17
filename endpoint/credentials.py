from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets

from .errors import EndpointError, require

TOKEN_BYTES = 32
DEFAULT_PBKDF2_ITERATIONS = 210_000
MIN_PBKDF2_ITERATIONS = 100_000
PBKDF2_ALGORITHM = "pbkdf2_sha256"
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{43,}$")


def generate_client_token() -> str:
	return secrets.token_urlsafe(TOKEN_BYTES)


def validate_client_token_strength(token: str) -> None:
	require(isinstance(token, str), "invalid_config", "client token must be a string")
	require(TOKEN_RE.fullmatch(token) is not None, "invalid_config", "client token is too weak")


def hash_client_token(token: str, *, allow_weak: bool = False, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> str:
	if not allow_weak:
		validate_client_token_strength(token)
	require(isinstance(iterations, int) and iterations >= MIN_PBKDF2_ITERATIONS, "invalid_config", "PBKDF2 iterations are too low")
	salt = secrets.token_bytes(16)
	digest = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, iterations)
	return f"{PBKDF2_ALGORITHM}:{iterations}:{_b64encode(salt)}:{_b64encode(digest)}"


def validate_client_token_hash(verifier: str) -> None:
	algorithm, iterations, salt, digest = _parse_verifier(verifier)
	require(algorithm == PBKDF2_ALGORITHM, "invalid_config", "unsupported client token hash algorithm")
	require(iterations >= MIN_PBKDF2_ITERATIONS, "invalid_config", "PBKDF2 iterations are too low")
	require(len(salt) >= 16, "invalid_config", "client token hash salt is too short")
	require(len(digest) == 32, "invalid_config", "client token hash digest is invalid")


def verify_client_token(token: str, verifier: str) -> bool:
	if not isinstance(token, str):
		return False
	try:
		algorithm, iterations, salt, expected = _parse_verifier(verifier)
		if algorithm != PBKDF2_ALGORITHM or iterations < MIN_PBKDF2_ITERATIONS:
			return False
	except EndpointError:
		return False
	actual = hashlib.pbkdf2_hmac("sha256", token.encode("utf-8"), salt, iterations)
	return hmac.compare_digest(actual, expected)


def _parse_verifier(verifier: str) -> tuple[str, int, bytes, bytes]:
	require(isinstance(verifier, str), "invalid_config", "client token hash must be a string")
	parts = verifier.split(":")
	require(len(parts) == 4, "invalid_config", "client token hash format is invalid")
	algorithm, iterations_raw, salt_raw, digest_raw = parts
	try:
		iterations = int(iterations_raw)
	except ValueError as exc:
		raise EndpointError("invalid_config", "client token hash iterations are invalid") from exc
	return algorithm, iterations, _b64decode(salt_raw), _b64decode(digest_raw)


def _b64encode(value: bytes) -> str:
	return base64.b64encode(value).decode("ascii")


def _b64decode(value: str) -> bytes:
	try:
		return base64.b64decode(value.encode("ascii"), validate=True)
	except Exception as exc:
		raise EndpointError("invalid_config", "client token hash base64 is invalid") from exc
