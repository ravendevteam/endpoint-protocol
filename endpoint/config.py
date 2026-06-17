from __future__ import annotations

from pathlib import Path
from typing import Any

from .credentials import validate_client_token_hash
from .errors import EndpointError, require
from .protocol import PROTOCOL_VERSION, parse_json_strict
from .server_core import ServerConfig
from .transport import FederationPolicy, normalize_server_url

SERVER_CONFIG_KEYS = {
	"protocol_version",
	"server_url",
	"state_dir",
	"hosted_identities",
	"client_token_hashes",
	"ca_bundle",
	"federation_policy",
	"lease_seconds",
	"rejected_policy",
	"debug_errors",
	"verify_hosted_identity_signatures",
}

FEDERATION_POLICY_KEYS = {
	"public_federation",
	"inbound_whitelist",
	"outbound_whitelist",
	"allow_private_networks",
	"allowed_ports",
	"mode",
}

FEDERATION_MODES = {"public", "inbound_whitelist", "outbound_whitelist", "whitelist", "internal"}


def load_server_config(path: Path) -> ServerConfig:
	try:
		raw = path.read_text(encoding="utf-8")
	except Exception as exc:
		raise EndpointError("invalid_config", "server config could not be read", detail=type(exc).__name__) from exc
	try:
		data = parse_json_strict(raw)
	except EndpointError as exc:
		raise EndpointError("invalid_config", "server config is invalid JSON", detail=exc.code) from exc
	require(isinstance(data, dict), "invalid_config", "server config must be a JSON object")
	_validate_exact_keys(data, SERVER_CONFIG_KEYS, "server config")
	require(data["protocol_version"] == PROTOCOL_VERSION, "invalid_config", "server config protocol version is unsupported")
	server_url = _require_string(data["server_url"], "server_url")
	try:
		normalize_server_url(server_url)
	except EndpointError as exc:
		raise EndpointError("invalid_config", "server_url is invalid", detail=exc.code) from exc
	state_dir = Path(_require_string(data["state_dir"], "state_dir"))
	hosted_identities = _require_identity_map(data["hosted_identities"])
	client_token_hashes = _require_token_hash_map(data["client_token_hashes"])
	ca_bundle = _require_optional_bool_or_string(data["ca_bundle"], "ca_bundle")
	policy = _load_federation_policy(data["federation_policy"])
	lease_seconds = _require_int_range(data["lease_seconds"], "lease_seconds", 1, 3600)
	rejected_policy = _require_string(data["rejected_policy"], "rejected_policy")
	require(rejected_policy in {"drop", "quarantine"}, "invalid_config", "rejected_policy is invalid")
	debug_errors = _require_bool(data["debug_errors"], "debug_errors")
	verify_hosted_identity_signatures = _require_bool(data["verify_hosted_identity_signatures"], "verify_hosted_identity_signatures")
	return ServerConfig(
		server_url=server_url,
		state_dir=state_dir,
		hosted_identities=hosted_identities,
		client_token_hashes=client_token_hashes,
		ca_bundle=ca_bundle,
		federation_policy=policy,
		lease_seconds=lease_seconds,
		rejected_policy=rejected_policy,
		debug_errors=debug_errors,
		verify_hosted_identity_signatures=verify_hosted_identity_signatures,
	)


def _load_federation_policy(value: Any) -> FederationPolicy:
	require(isinstance(value, dict), "invalid_config", "federation_policy must be an object")
	_validate_exact_keys(value, FEDERATION_POLICY_KEYS, "federation_policy")
	public_federation = _require_bool(value["public_federation"], "public_federation")
	inbound_whitelist = _require_string_set(value["inbound_whitelist"], "inbound_whitelist")
	outbound_whitelist = _require_string_set(value["outbound_whitelist"], "outbound_whitelist")
	allow_private_networks = _require_bool(value["allow_private_networks"], "allow_private_networks")
	allowed_ports = _require_port_set(value["allowed_ports"])
	mode = _require_string(value["mode"], "mode")
	require(mode in FEDERATION_MODES, "invalid_config", "federation policy mode is invalid")
	return FederationPolicy(
		public_federation=public_federation,
		inbound_whitelist=inbound_whitelist,
		outbound_whitelist=outbound_whitelist,
		allow_private_networks=allow_private_networks,
		allowed_ports=allowed_ports,
		mode=mode,
	)


def _validate_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
	actual = set(value)
	require(actual == expected, "invalid_config", f"{label} keys are invalid")


def _require_string(value: Any, field: str) -> str:
	require(isinstance(value, str) and value != "", "invalid_config", f"{field} must be a non-empty string")
	return value


def _require_bool(value: Any, field: str) -> bool:
	require(isinstance(value, bool), "invalid_config", f"{field} must be a boolean")
	return value


def _require_optional_bool_or_string(value: Any, field: str) -> str | bool:
	require(isinstance(value, bool) or isinstance(value, str), "invalid_config", f"{field} must be a boolean or string")
	require(not isinstance(value, str) or value != "", "invalid_config", f"{field} must not be empty")
	return value


def _require_int_range(value: Any, field: str, minimum: int, maximum: int) -> int:
	require(isinstance(value, int) and not isinstance(value, bool), "invalid_config", f"{field} must be an integer")
	require(minimum <= value <= maximum, "invalid_config", f"{field} is out of range")
	return value


def _require_identity_map(value: Any) -> dict[str, dict[str, Any]]:
	require(isinstance(value, dict), "invalid_config", "hosted_identities must be an object")
	out: dict[str, dict[str, Any]] = {}
	for client_ref, identity in value.items():
		require(isinstance(client_ref, str) and client_ref != "", "invalid_config", "hosted identity client_ref is invalid")
		require(isinstance(identity, dict), "invalid_config", "hosted identity must be an object")
		out[client_ref] = identity
	return out


def _require_token_hash_map(value: Any) -> dict[str, str]:
	require(isinstance(value, dict), "invalid_config", "client_token_hashes must be an object")
	out: dict[str, str] = {}
	for client_ref, verifier in value.items():
		require(isinstance(client_ref, str) and client_ref != "", "invalid_config", "client token hash client_ref is invalid")
		validate_client_token_hash(verifier)
		out[client_ref] = verifier
	return out


def _require_string_set(value: Any, field: str) -> set[str]:
	require(isinstance(value, list), "invalid_config", f"{field} must be a list")
	out: set[str] = set()
	for item in value:
		out.add(_require_string(item, field))
	return out


def _require_port_set(value: Any) -> set[int]:
	require(isinstance(value, list), "invalid_config", "allowed_ports must be a list")
	out: set[int] = set()
	for item in value:
		out.add(_require_int_range(item, "allowed_ports", 1, 65535))
	require(len(out) > 0, "invalid_config", "allowed_ports must not be empty")
	return out
