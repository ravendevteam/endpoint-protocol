from __future__ import annotations

import base64
import hashlib
import uuid
from pathlib import Path
from typing import Any

from .errors import EndpointError, require

PUBLIC_KEY_FILE = "public_key.asc"
SECRET_KEY_FILE = "secret_key.asc"
RAW_FINGERPRINT_FILE = "raw_openpgp_fingerprint.txt"


class OpenPgpContext:
	def __init__(self, key_store_dir: str | Path):
		self.key_store_dir = Path(key_store_dir)
		self.key_store_dir.mkdir(parents=True, exist_ok=True)
		self.home_dir = self.key_store_dir
		self.backend = "sequoia"

	def generate_identity(self, name: str | None = None, email: str | None = None) -> str:
		name = _safe_key_parameter(name or f"Endpoint {uuid.uuid4()}", "name")
		email = _safe_key_parameter(email or f"{uuid.uuid4()}@endpoint.local", "email")
		backend = _backend()
		try:
			identity = backend.generate_identity(name, email)
		except Exception as exc:
			raise _map_backend_error(exc, "crypto_failed", "OpenPGP identity generation failed") from exc
		raw_fingerprint = _require_backend_string(identity, "raw_fingerprint")
		public_key = _require_backend_string(identity, "public_key_armored")
		secret_key = _require_backend_string(identity, "secret_key_armored")
		_write_private_key_file(self._secret_key_path(), secret_key)
		self._public_key_path().write_text(public_key, encoding="utf-8")
		self._raw_fingerprint_path().write_text(raw_fingerprint, encoding="ascii")
		return raw_fingerprint

	def has_identity_material(self) -> bool:
		return self._raw_fingerprint_path().exists() or self._public_key_path().exists() or self._secret_key_path().exists()

	def export_public_key(self, key_fingerprint: str) -> str:
		public_key = self._read_public_key()
		raw_fingerprint = raw_openpgp_fingerprint(public_key)
		require(raw_fingerprint == key_fingerprint, "crypto_failed", "requested key is not available")
		return public_key

	def current_fingerprint(self) -> str:
		paths = (self._raw_fingerprint_path(), self._public_key_path(), self._secret_key_path())
		if not any(path.exists() for path in paths):
			raise EndpointError("crypto_failed", "key store is not initialized")
		if not all(path.exists() for path in paths):
			raise EndpointError("crypto_failed", "key store is incomplete")
		raw_fingerprint = self._read_raw_fingerprint()
		public_key = self._read_public_key()
		raw_public_fingerprint = raw_openpgp_fingerprint(public_key)
		require(raw_public_fingerprint == raw_fingerprint, "crypto_failed", "key store fingerprint does not match public key")
		self._read_secret_key()
		return raw_fingerprint

	def import_public_key(self, public_key_armored: str) -> None:
		raw_openpgp_fingerprint(public_key_armored)

	def sign_detached(self, key_fingerprint: str, payload: bytes) -> str:
		require(self._read_raw_fingerprint() == key_fingerprint, "crypto_failed", "requested signing key is not available")
		try:
			return _backend().sign_detached(self._read_secret_key(), payload)
		except Exception as exc:
			raise _map_backend_error(exc, "crypto_failed", "OpenPGP signing failed") from exc

	def encrypt_to(self, public_key_armored: str, payload: bytes) -> str:
		try:
			return _backend().encrypt_to(public_key_armored, payload)
		except Exception as exc:
			raise _map_backend_error(exc, "crypto_failed", "OpenPGP encryption failed") from exc

	def decrypt(self, ciphertext_armored: str) -> bytes:
		try:
			return bytes(_backend().decrypt(self._read_secret_key(), ciphertext_armored))
		except Exception as exc:
			raise _map_backend_error(exc, "malformed_ciphertext", "ciphertext could not be decrypted") from exc

	def _public_key_path(self) -> Path:
		return self.key_store_dir / PUBLIC_KEY_FILE

	def _secret_key_path(self) -> Path:
		return self.key_store_dir / SECRET_KEY_FILE

	def _raw_fingerprint_path(self) -> Path:
		return self.key_store_dir / RAW_FINGERPRINT_FILE

	def _read_public_key(self) -> str:
		try:
			return self._public_key_path().read_text(encoding="utf-8")
		except Exception as exc:
			raise EndpointError("crypto_failed", "public key is not available", detail=type(exc).__name__) from exc

	def _read_secret_key(self) -> str:
		try:
			return self._secret_key_path().read_text(encoding="utf-8")
		except Exception as exc:
			raise EndpointError("crypto_failed", "secret key is not available", detail=type(exc).__name__) from exc

	def _read_raw_fingerprint(self) -> str:
		try:
			return self._raw_fingerprint_path().read_text(encoding="ascii")
		except Exception as exc:
			raise EndpointError("crypto_failed", "key fingerprint is not available", detail=type(exc).__name__) from exc



def canonical_public_key_bytes(public_key_armored: str) -> bytes:
	try:
		return bytes(_backend().canonical_public_key_bytes(public_key_armored))
	except Exception as exc:
		raise _map_backend_error(exc, "invalid_envelope", "public key is invalid") from exc


def raw_openpgp_fingerprint(public_key_armored: str) -> str:
	try:
		return _backend().raw_openpgp_fingerprint(public_key_armored)
	except Exception as exc:
		raise _map_backend_error(exc, "invalid_envelope", "public key is invalid") from exc


def endpoint_fingerprint(public_key_armored: str) -> str:
	digest = hashlib.sha256(canonical_public_key_bytes(public_key_armored)).digest()
	encoded = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
	return f"ep1:{encoded}"


def display_fingerprint(machine_fingerprint: str) -> str:
	require(machine_fingerprint.startswith("ep1:"), "invalid_envelope", "invalid fingerprint")
	raw = machine_fingerprint[4:].upper()
	return "EP1 " + " ".join(raw[index:index + 4] for index in range(0, len(raw), 4))


def verify_detached(public_key_armored: str, payload: bytes, signature_armored: str) -> None:
	try:
		_backend().verify_detached(public_key_armored, payload, signature_armored)
	except Exception as exc:
		raise _map_backend_error(exc, "signature_invalid", "signature verification failed") from exc


def _backend() -> Any:
	try:
		import endpoint_openpgp_sequoia
	except Exception as exc:
		raise EndpointError("crypto_unavailable", "Sequoia OpenPGP backend is unavailable", detail=type(exc).__name__) from exc
	return endpoint_openpgp_sequoia


def _map_backend_error(exc: Exception, code: str, message: str) -> EndpointError:
	if isinstance(exc, EndpointError):
		return exc
	backend_name = exc.__class__.__name__
	detail = f"{backend_name}: {str(exc)}" if str(exc) else backend_name
	if backend_name == "SignatureInvalid":
		return EndpointError("signature_invalid", "signature verification failed", detail=detail)
	if backend_name == "MalformedCiphertext":
		return EndpointError("malformed_ciphertext", "ciphertext could not be decrypted", detail=detail)
	if backend_name == "CryptoFailed":
		return EndpointError(code, message, detail=detail)
	if backend_name in {"ModuleNotFoundError", "ImportError"}:
		return EndpointError("crypto_unavailable", "Sequoia OpenPGP backend is unavailable", detail=detail)
	return EndpointError(code, message, detail=detail)


def _require_backend_string(value: dict[str, Any], key: str) -> str:
	item = value.get(key)
	require(isinstance(item, str) and item != "", "crypto_failed", f"{key} was not returned by OpenPGP backend")
	return item


def _write_private_key_file(path: Path, contents: str) -> None:
	path.write_text(contents, encoding="utf-8")
	try:
		path.chmod(0o600)
	except OSError:
		pass


def _safe_key_parameter(value: str, field: str) -> str:
	require(isinstance(value, str) and value != "", "crypto_failed", f"{field} must be a non-empty string")
	require("\n" not in value and "\r" not in value, "crypto_failed", f"{field} must not contain line breaks")
	return value
