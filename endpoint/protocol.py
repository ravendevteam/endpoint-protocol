from __future__ import annotations

import json
import hashlib
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .errors import EndpointError, require

PROTOCOL_VERSION = "endpoint-poc-1"
MAX_METADATA_BYTES = 16 * 1024
MAX_IDENTITY_BYTES = 64 * 1024
MAX_ENVELOPE_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 8

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SAFE_FIELD_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")


@dataclass(frozen=True)
class ProtocolLimits:
	max_metadata_bytes: int = MAX_METADATA_BYTES
	max_identity_bytes: int = MAX_IDENTITY_BYTES
	max_envelope_bytes: int = MAX_ENVELOPE_BYTES
	max_json_depth: int = MAX_JSON_DEPTH


def now_iso() -> str:
	return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_json_strict(data: str | bytes) -> Any:
	def hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
		out: dict[str, Any] = {}
		for key, value in pairs:
			if key in out:
				raise EndpointError("invalid_envelope", "duplicate JSON key")
			out[key] = value
		return out

	try:
		return json.loads(data, object_pairs_hook=hook)
	except EndpointError:
		raise
	except Exception as exc:
		raise EndpointError("invalid_envelope", "invalid JSON", detail=str(exc)) from exc


def normalize_json(value: Any) -> Any:
	if value is None or isinstance(value, bool) or isinstance(value, int):
		return value
	if isinstance(value, float):
		raise EndpointError("invalid_envelope", "floating point values are not allowed")
	if isinstance(value, str):
		return unicodedata.normalize("NFC", value)
	if isinstance(value, list):
		return [normalize_json(item) for item in value]
	if isinstance(value, dict):
		out: dict[str, Any] = {}
		for key, item in value.items():
			require(isinstance(key, str), "invalid_envelope", "JSON object keys must be strings")
			nkey = unicodedata.normalize("NFC", key)
			require(nkey not in out, "invalid_envelope", "duplicate JSON key after normalization")
			out[nkey] = normalize_json(item)
		return out
	raise EndpointError("invalid_envelope", "unsupported JSON value")


def canonical_json_bytes(value: Any) -> bytes:
	normalized = normalize_json(value)
	return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def json_size(value: Any) -> int:
	return len(canonical_json_bytes(value))


def json_depth(value: Any) -> int:
	if isinstance(value, dict):
		if not value:
			return 1
		return 1 + max(json_depth(item) for item in value.values())
	if isinstance(value, list):
		if not value:
			return 1
		return 1 + max(json_depth(item) for item in value)
	return 1


def reject_controls(value: str, field: str) -> None:
	for char in value:
		if ord(char) < 0x20 or ord(char) == 0x7F:
			raise EndpointError("invalid_envelope", f"{field} contains a control character")


def validate_metadata(metadata: Any, limits: ProtocolLimits | None = None) -> None:
	limits = limits or ProtocolLimits()
	if metadata is None:
		return
	require(isinstance(metadata, dict), "invalid_envelope", "metadata must be an object or null")
	require(json_depth(metadata) <= limits.max_json_depth, "metadata_too_large", "metadata nesting is too deep")
	require(json_size(metadata) <= limits.max_metadata_bytes, "metadata_too_large", "metadata is too large")
	for key, value in metadata.items():
		require(isinstance(key, str), "invalid_envelope", "metadata field names must be strings")
		require(SAFE_FIELD_RE.match(key) is not None, "invalid_envelope", "metadata field name is invalid")
		if key == "username":
			require(isinstance(value, str), "invalid_envelope", "username must be a string")
			require(USERNAME_RE.match(value) is not None, "invalid_envelope", "username is invalid")
		elif key == "display_name":
			require(isinstance(value, str), "invalid_envelope", "display_name must be a string")
			reject_controls(value, "display_name")
			require(1 <= len(value) <= 128, "invalid_envelope", "display_name length is invalid")
		elif key == "status":
			require(isinstance(value, str), "invalid_envelope", "status must be a string")
			reject_controls(value, "status")
			require(len(value) <= 140, "invalid_envelope", "status length is invalid")


def validate_route(route: Any) -> None:
	require(isinstance(route, dict), "invalid_envelope", "route must be an object")
	require(isinstance(route.get("server_url"), str), "invalid_envelope", "route.server_url is required")
	require(isinstance(route.get("client_ref"), str), "invalid_envelope", "route.client_ref is required")
	require(route["client_ref"] != "", "invalid_envelope", "route.client_ref is required")


def validate_identity_envelope(identity: Any, limits: ProtocolLimits | None = None) -> None:
	limits = limits or ProtocolLimits()
	require(isinstance(identity, dict), "invalid_envelope", "identity must be an object")
	require(json_size(identity) <= limits.max_identity_bytes, "metadata_too_large", "identity envelope is too large")
	require(identity.get("protocol_version") == PROTOCOL_VERSION, "invalid_envelope", "unsupported protocol version")
	for field in ("client_ref", "public_key_armored", "endpoint_fingerprint", "identity_signature"):
		require(isinstance(identity.get(field), str) and identity[field], "invalid_envelope", f"{field} is required")
	validate_metadata(identity.get("metadata"), limits)


def validate_encrypted_envelope(envelope: Any, limits: ProtocolLimits | None = None) -> None:
	limits = limits or ProtocolLimits()
	require(isinstance(envelope, dict), "invalid_envelope", "message envelope must be an object")
	require(json_size(envelope) <= limits.max_envelope_bytes, "metadata_too_large", "message envelope is too large")
	require(envelope.get("protocol_version") == PROTOCOL_VERSION, "invalid_envelope", "unsupported protocol version")
	for field in ("message_id", "recipient_fingerprint", "created_at", "ciphertext_armored", "ciphertext_sha256"):
		require(isinstance(envelope.get(field), str) and envelope[field], "invalid_envelope", f"{field} is required")
	require(re.fullmatch(r"[0-9a-f]{64}", envelope["ciphertext_sha256"]) is not None, "invalid_envelope", "ciphertext_sha256 is invalid")
	actual_hash = hashlib.sha256(envelope["ciphertext_armored"].encode("utf-8")).hexdigest()
	require(actual_hash == envelope["ciphertext_sha256"], "invalid_envelope", "ciphertext hash does not match")
	validate_route(envelope.get("sender_route"))
	validate_route(envelope.get("recipient_route"))


def identity_signature_payload(identity: dict[str, Any]) -> dict[str, Any]:
	return {
		"protocol_version": identity["protocol_version"],
		"client_ref": identity["client_ref"],
		"public_key_armored": identity["public_key_armored"],
		"endpoint_fingerprint": identity["endpoint_fingerprint"],
		"metadata": identity.get("metadata"),
	}


def message_outer_compare_fields(envelope: dict[str, Any], payload: dict[str, Any]) -> list[str]:
	fields = ["message_id", "protocol_version", "sender_route", "recipient_route", "recipient_fingerprint", "created_at"]
	return [field for field in fields if envelope.get(field) != payload.get(field)]
