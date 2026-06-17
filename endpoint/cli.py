from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Any, Callable

import uvicorn

from .client_core import EndpointClient, ReceivedMessage
from .config import load_server_config
from .credentials import generate_client_token, hash_client_token, validate_client_token_hash
from .errors import EndpointError, require
from .protocol import PROTOCOL_VERSION, canonical_json_bytes, parse_json_strict, validate_identity_envelope, validate_metadata
from .server_core import create_app


class CliUsageError(Exception):
	pass


def main(argv: list[str] | None = None) -> int:
	parser = build_parser()
	args = parser.parse_args(argv)
	try:
		return args.handler(args.kv)
	except CliUsageError as exc:
		print(f"error: {exc}", file=sys.stderr)
		return 2
	except EndpointError as exc:
		_write_json(exc.safe_body(), sys.stderr)
		return 1


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(prog="endpoint")
	subparsers = parser.add_subparsers(dest="command", required=True)

	token = subparsers.add_parser("token")
	token_sub = token.add_subparsers(dest="token_command", required=True)
	_add_leaf(token_sub, "generate", _cmd_token_generate)
	_add_leaf(token_sub, "hash", _cmd_token_hash)

	identity = subparsers.add_parser("identity")
	identity_sub = identity.add_subparsers(dest="identity_command", required=True)
	_add_leaf(identity_sub, "export", _cmd_identity_export)

	server = subparsers.add_parser("server")
	server_sub = server.add_subparsers(dest="server_command", required=True)
	_add_leaf(server_sub, "init-config", _cmd_server_init_config)
	_add_leaf(server_sub, "validate-config", _cmd_server_validate_config)
	_add_leaf(server_sub, "run", _cmd_server_run)

	_add_leaf(subparsers, "discover", _cmd_discover)
	_add_leaf(subparsers, "send", _cmd_send)
	_add_leaf(subparsers, "receive", _cmd_receive)
	return parser


def _add_leaf(subparsers: argparse._SubParsersAction[Any], name: str, handler: Callable[[list[str]], int]) -> None:
	parser = subparsers.add_parser(name)
	parser.add_argument("kv", nargs=argparse.REMAINDER)
	parser.set_defaults(handler=handler)


def _cmd_token_generate(tokens: list[str]) -> int:
	_parse_key_values(tokens, scalar_keys=set())
	_write_json({"token": generate_client_token()})
	return 0


def _cmd_token_hash(tokens: list[str]) -> int:
	values = _parse_key_values(tokens, scalar_keys={"token"}, required_scalars={"token"})
	_write_json({"client_token_hash": hash_client_token(values["token"])})
	return 0


def _cmd_identity_export(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys=_CLIENT_KEYS | {"name", "email", "metadata_json", "out"},
		required_scalars={"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir"},
	)
	client = _client_from_values(values)
	metadata = _metadata_from_values(values)
	identity = client.export_identity(metadata)
	_write_json_file_if_requested(values.get("out"), identity)
	_write_json(identity)
	return 0


def _cmd_server_init_config(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys={"server_url", "state_dir", "ca_bundle", "allow_private_networks", "lease_seconds", "rejected_policy", "out"},
		list_keys={"allowed_port", "outbound_whitelist", "inbound_whitelist"},
		map_prefixes={"hosted_identity", "client_token_hash"},
		required_scalars={"server_url", "state_dir", "out"},
		required_maps={"hosted_identity", "client_token_hash"},
	)
	hosted_identities = _load_hosted_identities(values["hosted_identity"])
	client_token_hashes = values["client_token_hash"]
	require(set(hosted_identities) == set(client_token_hashes), "invalid_config", "client token hashes must match hosted identities")
	for verifier in client_token_hashes.values():
		validate_client_token_hash(verifier)
	allowed_ports = [_parse_int(item, "allowed_port", 1, 65535) for item in values["allowed_port"]]
	if not allowed_ports:
		allowed_ports = [443]
	allow_private = _parse_bool(values.get("allow_private_networks", "false"), "allow_private_networks")
	rejected_policy = values.get("rejected_policy", "drop")
	if rejected_policy not in {"drop", "quarantine"}:
		raise CliUsageError("rejected_policy must be drop or quarantine")
	lease_seconds = _parse_int(values.get("lease_seconds", "2"), "lease_seconds", 1, 3600)
	config = {
		"protocol_version": PROTOCOL_VERSION,
		"server_url": values["server_url"],
		"state_dir": values["state_dir"],
		"hosted_identities": hosted_identities,
		"client_token_hashes": client_token_hashes,
		"ca_bundle": _parse_optional_bool_or_string(values.get("ca_bundle", "true"), "ca_bundle"),
		"federation_policy": {
			"public_federation": True,
			"inbound_whitelist": values["inbound_whitelist"],
			"outbound_whitelist": values["outbound_whitelist"],
			"allow_private_networks": allow_private,
			"allowed_ports": allowed_ports,
			"mode": "internal" if allow_private else "public",
		},
		"lease_seconds": lease_seconds,
		"rejected_policy": rejected_policy,
		"debug_errors": False,
		"verify_hosted_identity_signatures": True,
	}
	_write_json_file(values["out"], config)
	_write_json(config)
	return 0


def _cmd_server_validate_config(tokens: list[str]) -> int:
	values = _parse_key_values(tokens, scalar_keys={"config"}, required_scalars={"config"})
	load_server_config(Path(values["config"]))
	_write_json({"status": "ok", "config": values["config"]})
	return 0


def _cmd_server_run(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys={"config", "host", "port", "ssl_certfile", "ssl_keyfile"},
		required_scalars={"config", "host", "port", "ssl_certfile", "ssl_keyfile"},
	)
	config = load_server_config(Path(values["config"]))
	app = create_app(config)
	uvicorn.run(
		app,
		host=values["host"],
		port=_parse_int(values["port"], "port", 1, 65535),
		ssl_certfile=values["ssl_certfile"],
		ssl_keyfile=values["ssl_keyfile"],
		ws="wsproto",
	)
	return 0


def _cmd_discover(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys=_CLIENT_KEYS | {"peer_server_url", "peer_client_ref", "identity_out"},
		required_scalars={"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir", "peer_server_url", "peer_client_ref"},
	)
	result = asyncio.run(_client_from_values(values).discover(values["peer_server_url"], values["peer_client_ref"]))
	_write_json_file_if_requested(values.get("identity_out"), result.identity)
	_write_json({
		"identity": result.identity,
		"route_warning": result.route_warning,
		"trust_state": result.trust_state,
	})
	return 0


def _cmd_send(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys=_CLIENT_KEYS | {"recipient_identity", "recipient_server_url", "body", "metadata_json", "message_id"},
		required_scalars={"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir", "recipient_identity", "recipient_server_url", "body"},
	)
	client = _client_from_values(values)
	client.require_existing_identity()
	result = asyncio.run(client.send_message(
		_load_json_object(values["recipient_identity"], "recipient_identity"),
		values["recipient_server_url"],
		values["body"],
		_metadata_from_values(values),
		values.get("message_id"),
	))
	_write_json({
		"message_id": result.message_id,
		"recipient_trust_state": result.recipient_trust_state,
	})
	return 0


def _cmd_receive(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys=_CLIENT_KEYS | {"limit", "timeout"},
		required_scalars={"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir"},
	)
	client = _client_from_values(values)
	client.require_existing_identity()
	messages = asyncio.run(client.receive_messages(
		limit=_parse_int(values.get("limit", "1"), "limit", 1, 1000),
		timeout=_parse_float(values.get("timeout", "5"), "timeout", 0.0),
	))
	_write_json({"messages": [_message_to_dict(message) for message in messages]})
	return 0


_CLIENT_KEYS = {"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir", "ca_bundle"}


def _client_from_values(values: dict[str, Any]) -> EndpointClient:
	return EndpointClient(
		client_ref=values["client_ref"],
		home_server_url=values["home_server_url"],
		auth_token=values["auth_token"],
		state_dir=values["state_dir"],
		key_store_dir=values["key_store_dir"],
		verify_tls=values.get("ca_bundle", True),
	)


def _metadata_from_values(values: dict[str, Any]) -> dict[str, Any] | None:
	if "metadata_json" not in values:
		return None
	metadata = parse_json_strict(values["metadata_json"])
	validate_metadata(metadata)
	return metadata


def _parse_key_values(
	tokens: list[str],
	*,
	scalar_keys: set[str],
	list_keys: set[str] | None = None,
	map_prefixes: set[str] | None = None,
	required_scalars: set[str] | None = None,
	required_maps: set[str] | None = None,
) -> dict[str, Any]:
	list_keys = list_keys or set()
	map_prefixes = map_prefixes or set()
	required_scalars = required_scalars or set()
	required_maps = required_maps or set()
	values: dict[str, Any] = {key: [] for key in list_keys}
	values.update({prefix: {} for prefix in map_prefixes})
	for token in tokens:
		if "=" not in token or token.startswith("="):
			raise CliUsageError(f"expected key=value argument, got {token!r}")
		key, value = token.split("=", 1)
		if key in scalar_keys:
			if key in values:
				raise CliUsageError(f"duplicate argument: {key}")
			values[key] = value
			continue
		if key in list_keys:
			values[key].append(value)
			continue
		map_match = _map_key_match(key, map_prefixes)
		if map_match is not None:
			prefix, item_key = map_match
			if item_key in values[prefix]:
				raise CliUsageError(f"duplicate argument: {key}")
			values[prefix][item_key] = value
			continue
		raise CliUsageError(f"unknown argument: {key}")
	missing = sorted(key for key in required_scalars if key not in values)
	if missing:
		raise CliUsageError(f"missing required argument: {missing[0]}")
	for prefix in sorted(required_maps):
		if not values.get(prefix):
			raise CliUsageError(f"missing required argument: {prefix}.<key>")
	return values


def _map_key_match(key: str, prefixes: set[str]) -> tuple[str, str] | None:
	for prefix in prefixes:
		stem = f"{prefix}."
		if key.startswith(stem):
			item_key = key[len(stem):]
			if item_key == "":
				raise CliUsageError(f"missing map key in argument: {key}")
			return prefix, item_key
	return None


def _parse_bool(value: str, field: str) -> bool:
	if value == "true":
		return True
	if value == "false":
		return False
	raise CliUsageError(f"{field} must be true or false")


def _parse_optional_bool_or_string(value: str, field: str) -> str | bool:
	if value in {"true", "false"}:
		return _parse_bool(value, field)
	return value


def _parse_int(value: str, field: str, minimum: int, maximum: int) -> int:
	try:
		parsed = int(value)
	except ValueError as exc:
		raise CliUsageError(f"{field} must be an integer") from exc
	if parsed < minimum or parsed > maximum:
		raise CliUsageError(f"{field} must be between {minimum} and {maximum}")
	return parsed


def _parse_float(value: str, field: str, minimum: float) -> float:
	try:
		parsed = float(value)
	except ValueError as exc:
		raise CliUsageError(f"{field} must be a number") from exc
	if parsed < minimum:
		raise CliUsageError(f"{field} must be at least {minimum:g}")
	return parsed


def _load_hosted_identities(paths: dict[str, str]) -> dict[str, dict[str, Any]]:
	identities: dict[str, dict[str, Any]] = {}
	for client_ref, path in paths.items():
		identity = _load_json_object(path, f"hosted_identity.{client_ref}")
		validate_identity_envelope(identity)
		require(identity["client_ref"] == client_ref, "invalid_config", "hosted identity client_ref mismatch")
		identities[client_ref] = identity
	return identities


def _load_json_object(path: str, field: str) -> dict[str, Any]:
	try:
		value = parse_json_strict(Path(path).read_text(encoding="utf-8"))
	except EndpointError:
		raise
	except Exception as exc:
		raise EndpointError("invalid_config", f"{field} could not be read", detail=type(exc).__name__) from exc
	require(isinstance(value, dict), "invalid_config", f"{field} must be a JSON object")
	return value


def _write_json_file_if_requested(path: str | None, value: Any) -> None:
	if path is not None:
		_write_json_file(path, value)


def _write_json_file(path: str, value: Any) -> None:
	target = Path(path)
	target.parent.mkdir(parents=True, exist_ok=True)
	target.write_bytes(canonical_json_bytes(value))


def _write_json(value: Any, stream: Any | None = None) -> None:
	stream = stream or sys.stdout
	stream.write(canonical_json_bytes(value).decode("utf-8"))
	stream.write("\n")


def _message_to_dict(message: ReceivedMessage) -> dict[str, Any]:
	return {
		"body": message.body,
		"message_id": message.message_id,
		"raw_payload": message.raw_payload,
		"sender_fingerprint": message.sender_fingerprint,
		"sender_metadata": message.sender_metadata,
		"sender_trust_state": message.sender_trust_state,
	}


if __name__ == "__main__":
	raise SystemExit(main())
