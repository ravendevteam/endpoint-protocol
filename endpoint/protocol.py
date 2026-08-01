from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .errors import EndpointError, require
from .transport import normalize_server_url

PROTOCOL_VERSION = "endpoint-poc-2"
MAX_METADATA_BYTES = 16 * 1024
MAX_IDENTITY_BYTES = 64 * 1024
MAX_ENVELOPE_BYTES = 1024 * 1024
MAX_CLAIM_BYTES = 128 * 1024
MAX_CONTENT_BYTES = 1024 * 1024
MAX_CONTENT_OBJECT_BYTES = 64 * 1024 * 1024
MAX_JSON_DEPTH = 8

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SAFE_FIELD_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
CONTENT_TYPE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$")
FINGERPRINT_RE = re.compile(r"^ep1:(?:[a-z2-7]{32}|[a-z2-7]{52})$")
DELIVERY_ROLES = {"to", "cc", "bcc"}


@dataclass(frozen=True)
class ProtocolLimits:
	max_metadata_bytes: int = MAX_METADATA_BYTES
	max_identity_bytes: int = MAX_IDENTITY_BYTES
	max_envelope_bytes: int = MAX_ENVELOPE_BYTES
	max_claim_bytes: int = MAX_CLAIM_BYTES
	max_content_bytes: int = MAX_CONTENT_BYTES
	max_content_object_bytes: int = MAX_CONTENT_OBJECT_BYTES
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


def validate_fingerprint(value: Any, field: str = "fingerprint") -> None:
	require(isinstance(value, str) and FINGERPRINT_RE.fullmatch(value) is not None, "invalid_envelope", f"{field} is invalid")


def validate_route(route: Any) -> None:
	require(isinstance(route, dict), "invalid_envelope", "route must be an object")
	require(isinstance(route.get("server_url"), str), "invalid_envelope", "route.server_url is required")
	require(isinstance(route.get("client_ref"), str), "invalid_envelope", "route.client_ref is required")
	require(route["client_ref"] != "", "invalid_envelope", "route.client_ref is required")
	try:
		normalize_server_url(route["server_url"])
	except EndpointError as exc:
		raise EndpointError("invalid_envelope", "route.server_url is invalid", detail=exc.code) from exc


def validate_identity_envelope(identity: Any, limits: ProtocolLimits | None = None) -> None:
	limits = limits or ProtocolLimits()
	require(isinstance(identity, dict), "invalid_envelope", "identity must be an object")
	require(json_size(identity) <= limits.max_identity_bytes, "metadata_too_large", "identity envelope is too large")
	require(identity.get("protocol_version") == PROTOCOL_VERSION, "invalid_envelope", "unsupported protocol version")
	for field in ("client_ref", "public_key_armored", "endpoint_fingerprint", "identity_signature"):
		require(isinstance(identity.get(field), str) and identity[field], "invalid_envelope", f"{field} is required")
	validate_fingerprint(identity["endpoint_fingerprint"], "endpoint_fingerprint")
	validate_metadata(identity.get("metadata"), limits)


def _require_protocol_object(value: Any, name: str, limit: int) -> dict[str, Any]:
	require(isinstance(value, dict), "invalid_envelope", f"{name} must be an object")
	require(json_depth(value) <= MAX_JSON_DEPTH, "metadata_too_large", f"{name} nesting is too deep")
	require(json_size(value) <= limit, "metadata_too_large", f"{name} is too large")
	require(value.get("protocol_version") == PROTOCOL_VERSION, "invalid_envelope", "unsupported protocol version")
	return value


def _require_nonempty_string(value: Any, field: str) -> None:
	require(isinstance(value, str) and value != "", "invalid_envelope", f"{field} is required")


def _require_timestamp(value: Any, field: str) -> None:
	_require_nonempty_string(value, field)
	try:
		parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
	except ValueError as exc:
		raise EndpointError("invalid_envelope", f"{field} is invalid", detail=str(exc)) from exc
	require(parsed.tzinfo is not None, "invalid_envelope", f"{field} must include a timezone")


def _require_sha256(value: Any, field: str) -> None:
	require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "invalid_envelope", f"{field} is invalid")


def validate_signed_content(content: Any, limits: ProtocolLimits | None = None) -> None:
	limits = limits or ProtocolLimits()
	content = _require_protocol_object(content, "signed content", limits.max_content_bytes)
	for field in ("content_id", "sender_fingerprint", "signature_algorithm", "signature"):
		_require_nonempty_string(content.get(field), field)
	validate_fingerprint(content["sender_fingerprint"], "sender_fingerprint")
	require(content["signature_algorithm"] == "openpgp-detached", "signature_invalid", "unsupported signature algorithm")
	payload = content.get("payload")
	require(isinstance(payload, dict), "invalid_envelope", "signed content payload must be an object")
	require(payload.get("protocol_version") == PROTOCOL_VERSION, "invalid_envelope", "signed content payload version is invalid")
	require(payload.get("content_id") == content["content_id"], "invalid_envelope", "signed content id does not match")
	_require_nonempty_string(payload.get("content_type"), "content_type")
	require(CONTENT_TYPE_RE.fullmatch(payload["content_type"]) is not None, "invalid_envelope", "content_type is invalid")
	_require_timestamp(payload.get("created_at"), "created_at")
	_require_nonempty_string(payload.get("sender_public_key_armored"), "sender_public_key_armored")
	validate_route(payload.get("sender_route"))
	validate_fingerprint(payload.get("sender_fingerprint"), "sender_fingerprint")
	require(payload["sender_fingerprint"] == content["sender_fingerprint"], "signature_invalid", "signed content sender mismatch")
	require("content" in payload, "invalid_envelope", "content is required")
	require(json_depth(payload["content"]) <= limits.max_json_depth, "metadata_too_large", "content nesting is too deep")
	require(json_size(payload["content"]) <= limits.max_content_bytes, "metadata_too_large", "content is too large")

	message_data = payload["content"] if payload["content_type"] == "message" else None
	if message_data is not None:
		require(isinstance(message_data, dict), "invalid_envelope", "message content must be an object")
		require(isinstance(message_data.get("body"), str), "invalid_envelope", "body must be a string")
		validate_metadata(message_data.get("sender_metadata"), limits)
		for field in ("visible_to", "visible_cc"):
			value = message_data.get(field, [])
			require(isinstance(value, list), "invalid_envelope", f"{field} must be an array")
			for route in value:
				validate_route(route)
		require("bcc" not in message_data and "visible_bcc" not in message_data, "invalid_envelope", "Bcc recipients must not be included in signed content")


def signed_content_hash(content: dict[str, Any]) -> str:
	validate_signed_content(content)
	return hashlib.sha256(canonical_json_bytes(content)).hexdigest()


def validate_content_object(content_object: Any, limits: ProtocolLimits | None = None) -> None:
	limits = limits or ProtocolLimits()
	content_object = _require_protocol_object(content_object, "content object", limits.max_content_object_bytes)
	for field in ("content_id", "content_sha256", "ciphertext_armored", "ciphertext_sha256"):
		_require_nonempty_string(content_object.get(field), field)
	_require_timestamp(content_object.get("created_at"), "created_at")
	_require_sha256(content_object["content_sha256"], "content_sha256")
	_require_sha256(content_object["ciphertext_sha256"], "ciphertext_sha256")
	require(
		hashlib.sha256(content_object["ciphertext_armored"].encode("utf-8")).hexdigest() == content_object["ciphertext_sha256"],
		"content_hash_mismatch",
		"content ciphertext hash does not match",
	)
	size_bytes = content_object.get("size_bytes")
	require(isinstance(size_bytes, int) and not isinstance(size_bytes, bool) and size_bytes >= 0, "invalid_envelope", "size_bytes is invalid")
	require(size_bytes <= limits.max_content_bytes, "metadata_too_large", "content object is too large")
	expires_at = content_object.get("expires_at")
	if expires_at is not None:
		_require_timestamp(expires_at, "expires_at")


def content_object_hash(content_object: dict[str, Any]) -> str:
	validate_content_object(content_object)
	return hashlib.sha256(canonical_json_bytes(content_object)).hexdigest()


def validate_delivery_claim(claim: Any, limits: ProtocolLimits | None = None) -> None:
	limits = limits or ProtocolLimits()
	claim = _require_protocol_object(claim, "delivery claim", limits.max_claim_bytes)
	for field in ("sender_fingerprint", "signature_algorithm", "signature"):
		_require_nonempty_string(claim.get(field), field)
	validate_fingerprint(claim["sender_fingerprint"], "sender_fingerprint")
	require(claim["signature_algorithm"] == "openpgp-detached", "signature_invalid", "unsupported signature algorithm")
	payload = claim.get("payload")
	require(isinstance(payload, dict), "invalid_envelope", "delivery claim payload must be an object")
	require(payload.get("protocol_version") == PROTOCOL_VERSION, "invalid_envelope", "delivery claim payload version is invalid")
	for field in ("message_id", "content_id", "recipient_role"):
		_require_nonempty_string(payload.get(field), field)
	_require_timestamp(payload.get("created_at"), "created_at")
	_require_sha256(payload.get("content_sha256"), "content_sha256")
	validate_route(payload.get("sender_route"))
	validate_route(payload.get("recipient_route"))
	validate_fingerprint(payload.get("recipient_fingerprint"), "recipient_fingerprint")
	validate_fingerprint(payload.get("sender_fingerprint"), "sender_fingerprint")
	require(payload["recipient_role"] in DELIVERY_ROLES, "invalid_envelope", "recipient_role is invalid")
	require(claim["sender_fingerprint"] == payload["sender_fingerprint"], "signature_invalid", "delivery claim sender mismatch")


def validate_delivery_envelope(envelope: Any, limits: ProtocolLimits | None = None) -> None:
	limits = limits or ProtocolLimits()
	envelope = _require_protocol_object(envelope, "delivery envelope", limits.max_envelope_bytes)
	for field in ("message_id", "content_id", "recipient_role", "delivery_ciphertext_armored", "delivery_ciphertext_sha256"):
		_require_nonempty_string(envelope.get(field), field)
	_require_timestamp(envelope.get("created_at"), "created_at")
	_require_sha256(envelope["content_sha256"], "content_sha256")
	_require_sha256(envelope["delivery_ciphertext_sha256"], "delivery_ciphertext_sha256")
	require(hashlib.sha256(envelope["delivery_ciphertext_armored"].encode("utf-8")).hexdigest() == envelope["delivery_ciphertext_sha256"], "invalid_envelope", "delivery ciphertext hash does not match")
	has_inline = "ciphertext_armored" in envelope or "ciphertext_sha256" in envelope
	has_reference = "content_ref" in envelope
	require(has_inline != has_reference, "invalid_envelope", "delivery envelope must contain exactly one content transport")
	if has_inline:
		_require_nonempty_string(envelope.get("ciphertext_armored"), "ciphertext_armored")
		_require_sha256(envelope.get("ciphertext_sha256"), "ciphertext_sha256")
		require(hashlib.sha256(envelope["ciphertext_armored"].encode("utf-8")).hexdigest() == envelope["ciphertext_sha256"], "invalid_envelope", "content ciphertext hash does not match")
	else:
		content_ref = envelope.get("content_ref")
		require(isinstance(content_ref, dict), "invalid_envelope", "content_ref must be an object")
		require(content_ref.get("content_id") == envelope["content_id"], "invalid_envelope", "content reference id does not match envelope")
		require(content_ref.get("content_sha256") == envelope["content_sha256"], "invalid_envelope", "content reference hash does not match envelope")
		_require_sha256(content_ref.get("content_sha256"), "content_ref.content_sha256")
	validate_route(envelope.get("sender_route"))
	validate_route(envelope.get("recipient_route"))
	validate_fingerprint(envelope.get("recipient_fingerprint"), "recipient_fingerprint")
	require(envelope["recipient_role"] in DELIVERY_ROLES, "invalid_envelope", "recipient_role is invalid")


def delivery_envelope_uses_content_reference(envelope: dict[str, Any]) -> bool:
	validate_delivery_envelope(envelope)
	return "content_ref" in envelope


def delivery_outer_compare_fields(envelope: dict[str, Any], claim_payload: dict[str, Any]) -> list[str]:
	fields = [
		"message_id",
		"protocol_version",
		"content_id",
		"content_sha256",
		"sender_route",
		"recipient_route",
		"recipient_fingerprint",
		"recipient_role",
		"created_at",
	]
	return [field for field in fields if envelope.get(field) != claim_payload.get(field)]


validate_encrypted_envelope = validate_delivery_envelope


def identity_signature_payload(identity: dict[str, Any]) -> dict[str, Any]:
	return {
		"protocol_version": identity["protocol_version"],
		"client_ref": identity["client_ref"],
		"public_key_armored": identity["public_key_armored"],
		"endpoint_fingerprint": identity["endpoint_fingerprint"],
		"metadata": identity.get("metadata"),
	}


def message_outer_compare_fields(envelope: dict[str, Any], payload: dict[str, Any]) -> list[str]:
	return delivery_outer_compare_fields(envelope, payload)
