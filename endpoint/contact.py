from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from .crypto import endpoint_fingerprint
from .errors import EndpointError, require
from .protocol import PROTOCOL_VERSION, validate_identity_envelope, validate_metadata
from .transport import normalize_server_url

CONTACT_KIND = "endpoint-contact"
CONTACT_URI_SCHEME = "endpoint"
CONTACT_URI_PATH = "contact"
CONTACT_URI_QUERY_KEYS = {"server_url", "client_ref", "fingerprint", "display_name", "username"}
FINGERPRINT_RE = re.compile(r"^ep1:[a-z2-7]{52}$")
CLIENT_REF_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def validate_endpoint_fingerprint(fingerprint: Any) -> str:
	require(isinstance(fingerprint, str) and FINGERPRINT_RE.fullmatch(fingerprint) is not None, "invalid_contact", "endpoint fingerprint is invalid")
	return fingerprint


def contact_route_key(server_url: str, client_ref: str) -> str:
	return f"{_normalize_contact_server_url(server_url)}|{_validate_client_ref(client_ref)}"


def contact_from_identity(server_url: str, identity: dict[str, Any]) -> dict[str, Any]:
	validate_identity_envelope(identity)
	computed = endpoint_fingerprint(identity["public_key_armored"])
	require(computed == identity["endpoint_fingerprint"], "invalid_contact", "identity fingerprint does not match public key")
	metadata = identity.get("metadata")
	validate_metadata(metadata)
	return {
		"kind": CONTACT_KIND,
		"protocol_version": PROTOCOL_VERSION,
		"server_url": _normalize_contact_server_url(server_url),
		"client_ref": _validate_client_ref(identity["client_ref"]),
		"endpoint_fingerprint": validate_endpoint_fingerprint(identity["endpoint_fingerprint"]),
		"metadata": metadata,
	}


def normalize_contact(value: Any) -> dict[str, Any]:
	require(isinstance(value, dict), "invalid_contact", "contact must be a JSON object")
	require(value.get("kind") == CONTACT_KIND, "invalid_contact", "contact kind is invalid")
	require(value.get("protocol_version") == PROTOCOL_VERSION, "invalid_contact", "contact protocol version is unsupported")
	server_url = _normalize_contact_server_url(_require_string(value.get("server_url"), "server_url"))
	client_ref = _validate_client_ref(value.get("client_ref"))
	fingerprint = validate_endpoint_fingerprint(value.get("endpoint_fingerprint"))
	metadata = value.get("metadata")
	validate_metadata(metadata)
	out = {
		"kind": CONTACT_KIND,
		"protocol_version": PROTOCOL_VERSION,
		"server_url": server_url,
		"client_ref": client_ref,
		"endpoint_fingerprint": fingerprint,
		"metadata": metadata,
	}
	public_identity = value.get("public_identity")
	if public_identity is not None:
		validate_identity_envelope(public_identity)
		require(public_identity["client_ref"] == client_ref, "invalid_contact", "contact identity client_ref mismatch")
		require(public_identity["endpoint_fingerprint"] == fingerprint, "invalid_contact", "contact identity fingerprint mismatch")
		out["public_identity"] = public_identity
	return out


def contact_to_uri(contact: dict[str, Any]) -> str:
	normalized = normalize_contact(contact)
	query = {
		"server_url": normalized["server_url"],
		"client_ref": normalized["client_ref"],
		"fingerprint": normalized["endpoint_fingerprint"],
	}
	metadata = normalized.get("metadata")
	if isinstance(metadata, dict):
		for key in ("display_name", "username"):
			value = metadata.get(key)
			if isinstance(value, str):
				query[key] = value
	return f"{CONTACT_URI_SCHEME}:{CONTACT_URI_PATH}?{urlencode(query)}"


def contact_from_uri(uri: str) -> dict[str, Any]:
	require(isinstance(uri, str) and uri != "", "invalid_contact", "contact URI is required")
	parsed = urlparse(uri)
	require(parsed.scheme == CONTACT_URI_SCHEME and parsed.path == CONTACT_URI_PATH, "invalid_contact", "contact URI kind is unsupported")
	require(parsed.params == "" and parsed.fragment == "", "invalid_contact", "contact URI must not include params or fragment")
	query = parse_qs(parsed.query, keep_blank_values=True, strict_parsing=False)
	unknown = sorted(set(query) - CONTACT_URI_QUERY_KEYS)
	if unknown:
		require(False, "invalid_contact", f"contact URI field is unsupported: {unknown[0]}")
	server_url = _one_query_value(query, "server_url")
	client_ref = _one_query_value(query, "client_ref")
	fingerprint = _one_query_value(query, "fingerprint")
	metadata: dict[str, str] = {}
	for key in ("display_name", "username"):
		value = query.get(key)
		if value is not None:
			require(len(value) == 1 and value[0] != "", "invalid_contact", f"contact {key} is invalid")
			metadata[key] = value[0]
	contact = {
		"kind": CONTACT_KIND,
		"protocol_version": PROTOCOL_VERSION,
		"server_url": server_url,
		"client_ref": client_ref,
		"endpoint_fingerprint": fingerprint,
		"metadata": metadata or None,
	}
	return normalize_contact(contact)


def _one_query_value(query: dict[str, list[str]], key: str) -> str:
	values = query.get(key)
	require(values is not None and len(values) == 1 and values[0] != "", "invalid_contact", f"contact {key} is required")
	return values[0]


def _require_string(value: Any, field: str) -> str:
	require(isinstance(value, str) and value != "", "invalid_contact", f"contact {field} is required")
	return value


def _normalize_contact_server_url(server_url: str) -> str:
	try:
		return normalize_server_url(server_url)
	except EndpointError as exc:
		raise EndpointError("invalid_contact", "contact server_url is invalid", detail=exc.code) from exc


def _validate_client_ref(value: Any) -> str:
	require(isinstance(value, str) and CLIENT_REF_RE.fullmatch(value) is not None, "invalid_contact", "contact client_ref is invalid")
	return value
