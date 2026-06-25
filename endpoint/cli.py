from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import shutil
import ssl
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

import httpx
import uvicorn

from .client_core import EndpointClient, ReceivedMessage
from .contact import contact_from_identity, contact_from_uri, contact_route_key, contact_to_uri, normalize_contact, validate_endpoint_fingerprint
from .config import load_server_config
from .credentials import generate_client_token, hash_client_token, validate_client_token_hash
from .crypto import endpoint_fingerprint, verify_detached
from .errors import EndpointError, require
from .protocol import (
	PROTOCOL_VERSION,
	canonical_json_bytes,
	identity_signature_payload,
	now_iso,
	parse_json_strict,
	validate_identity_envelope,
	validate_metadata,
)
from .server_core import create_app
from .transport import httpx_verify_config, normalize_server_url


class CliUsageError(Exception):
	pass


IDENTITY_SIGNATURE_HINT = "Sync system clocks, regenerate the identity or enrollment bundle, and retry."
CLOCK_SKEW_HINT = "Sync system clocks with UTC and retry. On Windows, run: w32tm /resync."
CLOCK_SKEW_LIMIT_SECONDS = 30


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
	except (OSError, ssl.SSLError) as exc:
		_write_json(EndpointError("io_failed", "operation failed", detail=type(exc).__name__).safe_body(), sys.stderr)
		return 1
	except Exception as exc:
		_write_json(EndpointError("internal_error", "unexpected CLI failure", detail=type(exc).__name__).safe_body(), sys.stderr)
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

	contact = subparsers.add_parser("contact")
	contact_sub = contact.add_subparsers(dest="contact_command", required=True)
	_add_leaf(contact_sub, "export", _cmd_contact_export)
	_add_leaf(contact_sub, "import", _cmd_contact_import)
	_add_leaf(contact_sub, "list", _cmd_contact_list)
	_add_leaf(contact_sub, "show", _cmd_contact_show)

	server = subparsers.add_parser("server")
	server_sub = server.add_subparsers(dest="server_command", required=True)
	_add_leaf(server_sub, "init-config", _cmd_server_init_config)
	_add_leaf(server_sub, "validate-config", _cmd_server_validate_config)
	_add_leaf(server_sub, "run", _cmd_server_run)

	setup = subparsers.add_parser("setup")
	setup_sub = setup.add_subparsers(dest="setup_command", required=True)
	_add_leaf(setup_sub, "host-init", _cmd_setup_host_init)
	_add_leaf(setup_sub, "invite", _cmd_setup_invite)
	_add_leaf(setup_sub, "join", _cmd_setup_join)
	_add_leaf(setup_sub, "enroll", _cmd_setup_enroll)
	_add_leaf(setup_sub, "run", _cmd_setup_run)

	_add_leaf(subparsers, "discover", _cmd_discover)
	_add_leaf(subparsers, "send", _cmd_send)
	_add_leaf(subparsers, "receive", _cmd_receive)
	_add_leaf(subparsers, "doctor", _cmd_doctor)
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


def _cmd_contact_export(tokens: list[str]) -> int:
	values = _parse_key_values(tokens, scalar_keys={"profile", "out"}, required_scalars={"profile"})
	profile = _load_client_profile(Path(values["profile"]))
	identity = _load_json_object(profile["identity_path"], "profile identity")
	_verify_identity_signature(identity)
	contact = contact_from_identity(profile["home_server_url"], identity)
	contact_uri = contact_to_uri(contact)
	if "out" in values:
		target = Path(values["out"])
		target.parent.mkdir(parents=True, exist_ok=True)
		target.write_text(contact_uri, encoding="utf-8")
	_write_json({"contact_uri": contact_uri, "contact": contact})
	return 0


def _cmd_contact_import(tokens: list[str]) -> int:
	values = _parse_key_values(tokens, scalar_keys={"profile", "uri", "contact", "out"}, required_scalars={"profile"})
	require(("uri" in values) != ("contact" in values), "invalid_contact", "provide exactly one of uri or contact")
	profile = _load_client_profile(Path(values["profile"]))
	if "uri" in values:
		contact = contact_from_uri(values["uri"])
	else:
		contact = normalize_contact(_load_json_object(values["contact"], "contact"))
	client = _client_from_values(_client_values_from_profile(profile))
	contact, route_key = _remember_contact(profile, client, contact)
	if "out" in values:
		_write_json_file(values["out"], contact)
	_write_json({
		"status": "ok",
		"client_ref": contact["client_ref"],
		"server_url": contact["server_url"],
		"endpoint_fingerprint": contact["endpoint_fingerprint"],
		"route_key": route_key,
		"pin_state": "pinned",
		"trust_state": client.trust_state(contact["endpoint_fingerprint"]),
	})
	return 0


def _cmd_contact_list(tokens: list[str]) -> int:
	values = _parse_key_values(tokens, scalar_keys={"profile"}, required_scalars={"profile"})
	profile = _load_client_profile(Path(values["profile"]))
	client = _client_from_values(_client_values_from_profile(profile))
	contacts = []
	for route_key, item in sorted(_load_contact_index(profile).items()):
		contacts.append({
			"route_key": route_key,
			"server_url": item["server_url"],
			"client_ref": item["client_ref"],
			"endpoint_fingerprint": item["endpoint_fingerprint"],
			"trust_state": client.trust_state(item["endpoint_fingerprint"]),
		})
	_write_json({"contacts": contacts})
	return 0


def _cmd_contact_show(tokens: list[str]) -> int:
	values = _parse_key_values(tokens, scalar_keys={"profile", "server_url", "client_ref"}, required_scalars={"profile", "server_url", "client_ref"})
	profile = _load_client_profile(Path(values["profile"]))
	server_url = _normalize_cli_url(values["server_url"], "server_url")
	contact = _load_contact_by_route(profile, server_url, values["client_ref"])
	require(contact is not None, "contact_not_found", "contact was not found for this route")
	client = _client_from_values(_client_values_from_profile(profile))
	_write_json({
		"route_key": contact_route_key(server_url, values["client_ref"]),
		"contact": contact,
		"trust_state": client.trust_state(contact["endpoint_fingerprint"]),
	})
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
	config = _server_config_document(
		server_url=_normalize_cli_url(values["server_url"], "server_url"),
		state_dir=Path(values["state_dir"]),
		hosted_identities=hosted_identities,
		client_token_hashes=client_token_hashes,
		ca_bundle=_parse_optional_bool_or_string(values.get("ca_bundle", "true"), "ca_bundle"),
		allowed_ports=allowed_ports,
		allow_private_networks=allow_private,
		rejected_policy=rejected_policy,
		lease_seconds=lease_seconds,
	)
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


def _cmd_setup_host_init(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys={
			"workspace",
			"server_url",
			"bind_host",
			"port",
			"owner_ref",
			"owner_name",
			"owner_email",
			"tls",
			"ssl_certfile",
			"ssl_keyfile",
			"ca_bundle",
		},
		required_scalars={"workspace", "server_url", "bind_host", "port", "owner_ref", "owner_name"},
	)
	workspace = Path(values["workspace"])
	server_url = _normalize_cli_url(values["server_url"], "server_url")
	port = _parse_int(values["port"], "port", 1, 65535)
	_require_url_port(server_url, port)
	bind_host = values["bind_host"]
	owner_ref = _validate_client_ref(values["owner_ref"])
	owner_name = values["owner_name"]
	owner_email = values.get("owner_email", f"{owner_ref}@endpoint.test")
	workspace.mkdir(parents=True, exist_ok=True)
	tls_paths = _prepare_tls(workspace, server_url, values)
	owner_dir = workspace / "clients" / owner_ref
	state_dir = owner_dir / "state"
	key_store_dir = owner_dir / "keys"
	identity_path = owner_dir / "identity.json"
	profile_path = owner_dir / "profile.json"
	contacts_dir = owner_dir / "contacts"
	token = generate_client_token()
	client = EndpointClient(
		client_ref=owner_ref,
		home_server_url=server_url,
		auth_token=token,
		state_dir=state_dir,
		key_store_dir=key_store_dir,
		verify_tls=str(tls_paths["ca_bundle"]),
	)
	client.ensure_identity(owner_name, owner_email)
	metadata = {"username": owner_ref, "display_name": owner_name}
	identity = client.export_identity(metadata)
	_write_json_file(identity_path, identity)
	profile = _client_profile_document(
		profile_path=profile_path,
		client_ref=owner_ref,
		home_server_url=server_url,
		auth_token=token,
		state_dir=state_dir,
		key_store_dir=key_store_dir,
		ca_bundle=tls_paths["ca_bundle"],
		identity_path=identity_path,
		contacts_dir=contacts_dir,
		metadata=metadata,
	)
	_write_json_file(profile_path, profile)
	server_config_path = workspace / "server.json"
	server_state_dir = workspace / "server-state"
	config = _server_config_document(
		server_url=server_url,
		state_dir=server_state_dir,
		hosted_identities={owner_ref: identity},
		client_token_hashes={owner_ref: hash_client_token(token)},
		ca_bundle=str(tls_paths["ca_bundle"]),
		allowed_ports=[port],
		allow_private_networks=True,
		rejected_policy="drop",
		lease_seconds=2,
	)
	_write_json_file(server_config_path, config)
	workspace_doc = {
		"protocol_version": PROTOCOL_VERSION,
		"kind": "endpoint-demo-host-workspace",
		"server_url": server_url,
		"bind_host": bind_host,
		"port": port,
		"server_config": _relative_path(server_config_path, workspace),
		"ssl_certfile": _relative_path(tls_paths["ssl_certfile"], workspace),
		"ssl_keyfile": _relative_path(tls_paths["ssl_keyfile"], workspace),
		"ca_bundle": _relative_path(tls_paths["ca_bundle"], workspace),
		"clients_dir": "clients",
		"pending_invites_dir": "pending-invites",
		"hosted_identities_dir": "hosted-identities",
	}
	_write_json_file(workspace / "workspace.json", workspace_doc)
	_write_json({
		"status": "ok",
		"workspace": str(workspace),
		"server_url": server_url,
		"server_config": str(server_config_path),
		"owner_profile": str(profile_path),
		"ca_bundle": str(tls_paths["ca_bundle"]),
		"ssl_certfile": str(tls_paths["ssl_certfile"]),
		"ssl_keyfile": str(tls_paths["ssl_keyfile"]),
	})
	return 0


def _cmd_setup_invite(tokens: list[str]) -> int:
	values = _parse_key_values(tokens, scalar_keys={"workspace", "client_ref", "out"}, required_scalars={"workspace", "client_ref", "out"})
	workspace = Path(values["workspace"])
	client_ref = _validate_client_ref(values["client_ref"])
	workspace_doc = _load_workspace(workspace)
	ca_path = _resolve_path(workspace_doc["ca_bundle"], workspace)
	require(ca_path.exists(), "invalid_config", "workspace CA bundle is missing")
	token = generate_client_token()
	pending_dir = workspace / workspace_doc["pending_invites_dir"]
	pending_dir.mkdir(parents=True, exist_ok=True)
	_write_json_file(pending_dir / f"{_safe_file_stem(client_ref)}.json", {
		"protocol_version": PROTOCOL_VERSION,
		"client_ref": client_ref,
		"client_token_hash": hash_client_token(token),
	})
	invite = {
		"protocol_version": PROTOCOL_VERSION,
		"kind": "endpoint-demo-invite",
		"created_at_utc": now_iso(),
		"server_url": workspace_doc["server_url"],
		"client_ref": client_ref,
		"auth_token": token,
		"ca_bundle": "ca.pem",
	}
	out_path = Path(values["out"])
	_write_invite_zip(out_path, invite, ca_path)
	_write_json({"status": "ok", "client_ref": client_ref, "invite": str(out_path)})
	return 0


def _cmd_setup_join(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys={"invite", "workspace", "name", "email", "out"},
		required_scalars={"invite", "workspace", "name", "out"},
	)
	workspace = Path(values["workspace"])
	workspace.mkdir(parents=True, exist_ok=True)
	invite, ca_bytes = _read_invite_zip(Path(values["invite"]))
	server_url = _normalize_cli_url(invite["server_url"], "server_url")
	client_ref = _validate_client_ref(invite["client_ref"])
	ca_path = workspace / "ca.pem"
	ca_path.write_bytes(ca_bytes)
	state_dir = workspace / "state"
	key_store_dir = workspace / "keys"
	identity_path = workspace / "identity.json"
	profile_path = workspace / "profile.json"
	contacts_dir = workspace / "contacts"
	name = values["name"]
	email = values.get("email", f"{client_ref}@endpoint.test")
	client = EndpointClient(
		client_ref=client_ref,
		home_server_url=server_url,
		auth_token=invite["auth_token"],
		state_dir=state_dir,
		key_store_dir=key_store_dir,
		verify_tls=str(ca_path),
	)
	client.ensure_identity(name, email)
	metadata = {"username": client_ref, "display_name": name}
	identity = client.export_identity(metadata)
	_write_json_file(identity_path, identity)
	profile = _client_profile_document(
		profile_path=profile_path,
		client_ref=client_ref,
		home_server_url=server_url,
		auth_token=invite["auth_token"],
		state_dir=state_dir,
		key_store_dir=key_store_dir,
		ca_bundle=ca_path,
		identity_path=identity_path,
		contacts_dir=contacts_dir,
		metadata=metadata,
	)
	_write_json_file(profile_path, profile)
	enrollment = {
		"protocol_version": PROTOCOL_VERSION,
		"kind": "endpoint-demo-enrollment",
		"created_at_utc": now_iso(),
		"server_url": server_url,
		"client_ref": client_ref,
		"identity_file": "identity.json",
	}
	out_path = Path(values["out"])
	_write_enrollment_zip(out_path, enrollment, identity)
	_check_enrollment_bundle(out_path)
	_write_json({
		"status": "ok",
		"client_ref": client_ref,
		"profile": str(profile_path),
		"enrollment": str(out_path),
	})
	return 0


def _cmd_setup_enroll(tokens: list[str]) -> int:
	values = _parse_key_values(tokens, scalar_keys={"workspace", "enrollment"}, required_scalars={"workspace", "enrollment"})
	workspace = Path(values["workspace"])
	workspace_doc = _load_workspace(workspace)
	enrollment, identity = _check_enrollment_bundle(Path(values["enrollment"]))
	client_ref = _validate_client_ref(enrollment["client_ref"])
	pending_path = workspace / workspace_doc["pending_invites_dir"] / f"{_safe_file_stem(client_ref)}.json"
	require(pending_path.exists(), "invalid_config", "pending invite was not found for this enrollment")
	pending = _load_json_object(str(pending_path), "pending invite")
	require(pending.get("client_ref") == client_ref, "invalid_config", "pending invite client_ref mismatch")
	token_hash = pending.get("client_token_hash")
	require(isinstance(token_hash, str), "invalid_config", "pending invite token hash is missing")
	validate_client_token_hash(token_hash)
	hosted_dir = workspace / workspace_doc["hosted_identities_dir"]
	hosted_dir.mkdir(parents=True, exist_ok=True)
	identity_path = hosted_dir / f"{_safe_file_stem(client_ref)}.identity.json"
	_write_json_file(identity_path, identity)
	config_path = _resolve_path(workspace_doc["server_config"], workspace)
	config = _load_json_object(str(config_path), "server config")
	hosted_identities = config.get("hosted_identities")
	client_token_hashes = config.get("client_token_hashes")
	require(isinstance(hosted_identities, dict), "invalid_config", "server config hosted_identities is invalid")
	require(isinstance(client_token_hashes, dict), "invalid_config", "server config client_token_hashes is invalid")
	hosted_identities[client_ref] = identity
	client_token_hashes[client_ref] = token_hash
	_write_json_file(config_path, config)
	try:
		pending_path.unlink()
	except FileNotFoundError:
		pass
	_write_json({
		"status": "ok",
		"client_ref": client_ref,
		"identity": str(identity_path),
		"server_config": str(config_path),
		"restart_required": True,
	})
	return 0


def _cmd_setup_run(tokens: list[str]) -> int:
	values = _parse_key_values(tokens, scalar_keys={"workspace"}, required_scalars={"workspace"})
	workspace = Path(values["workspace"])
	workspace_doc = _load_workspace(workspace)
	config_path = _resolve_path(workspace_doc["server_config"], workspace)
	config = load_server_config(config_path)
	app = create_app(config)
	uvicorn.run(
		app,
		host=workspace_doc["bind_host"],
		port=_parse_int(str(workspace_doc["port"]), "port", 1, 65535),
		ssl_certfile=str(_resolve_path(workspace_doc["ssl_certfile"], workspace)),
		ssl_keyfile=str(_resolve_path(workspace_doc["ssl_keyfile"], workspace)),
		ws="wsproto",
	)
	return 0


def _cmd_discover(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys=_CLIENT_KEYS | {"profile", "peer_server_url", "peer_client_ref", "expected_fingerprint", "identity_out"},
	)
	if "profile" in values:
		profile = _load_client_profile(Path(values["profile"]))
		client_values = _client_values_from_profile(profile)
	else:
		profile = None
		client_values = values
		_require_arguments(client_values, {"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir", "peer_server_url", "peer_client_ref"})
	_require_arguments(values, {"peer_client_ref"})
	contact = None
	peer_server_url = values.get("peer_server_url")
	expected_fingerprint = values.get("expected_fingerprint")
	if profile is not None:
		if peer_server_url is not None:
			peer_server_url = _normalize_cli_url(peer_server_url, "peer_server_url")
			contact = _load_contact_by_route(profile, peer_server_url, values["peer_client_ref"])
			if contact is not None:
				if expected_fingerprint is not None:
					require(expected_fingerprint == contact["endpoint_fingerprint"], "contact_fingerprint_mismatch", "expected fingerprint does not match contact pin")
				expected_fingerprint = contact["endpoint_fingerprint"]
		else:
			require(not _contacts_for_client_ref(profile, values["peer_client_ref"]), "contact_route_required", "server_url is required for imported contacts")
			peer_server_url = profile["home_server_url"]
	require(isinstance(peer_server_url, str) and peer_server_url != "", "invalid_config", "peer_server_url is required")
	client = _client_from_values(client_values)
	result = asyncio.run(client.discover(peer_server_url, values["peer_client_ref"], expected_fingerprint))
	if profile is not None:
		_write_contact(profile, peer_server_url, values["peer_client_ref"], result.identity)
		if result.pin_state == "matched":
			_remember_contact(profile, client, contact_from_identity(peer_server_url, result.identity))
	_write_json_file_if_requested(values.get("identity_out"), result.identity)
	_write_json({
		"identity": result.identity,
		"route_warning": result.route_warning,
		"pin_state": result.pin_state,
		"trust_state": result.trust_state,
	})
	return 0


def _cmd_send(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys=_CLIENT_KEYS | {"profile", "to", "recipient_identity", "recipient_server_url", "body", "metadata_json", "message_id"},
	)
	_require_arguments(values, {"body"})
	if "profile" in values:
		profile = _load_client_profile(Path(values["profile"]))
		_require_profile_clock_sync(profile)
		client_values = _client_values_from_profile(profile)
		client = _client_from_values(client_values)
		sender_metadata = _metadata_from_values(values) if "metadata_json" in values else profile.get("metadata")
		recipient_pin_state = None
		if "recipient_identity" in values:
			recipient_identity = _load_json_object(values["recipient_identity"], "recipient_identity")
			recipient_server_url = values.get("recipient_server_url", profile["home_server_url"])
		else:
			_require_arguments(values, {"to"})
			contact = None
			recipient_server_url = values.get("recipient_server_url")
			if recipient_server_url is not None:
				recipient_server_url = _normalize_cli_url(recipient_server_url, "recipient_server_url")
				contact = _load_contact_by_route(profile, recipient_server_url, values["to"])
			else:
				require(not _contacts_for_client_ref(profile, values["to"]), "contact_route_required", "recipient_server_url is required for imported contacts")
				recipient_server_url = profile["home_server_url"]
			if contact is not None:
				discovery = asyncio.run(client.discover(contact["server_url"], contact["client_ref"], contact["endpoint_fingerprint"]))
				recipient_pin_state = discovery.pin_state
			else:
				discovery = asyncio.run(client.discover(recipient_server_url, values["to"]))
			recipient_identity = discovery.identity
			_write_contact(profile, recipient_server_url, values["to"], recipient_identity)
	else:
		_require_arguments(values, {"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir", "recipient_identity", "recipient_server_url"})
		client = _client_from_values(values)
		client.require_existing_identity()
		sender_metadata = _metadata_from_values(values)
		recipient_identity = _load_json_object(values["recipient_identity"], "recipient_identity")
		recipient_server_url = values["recipient_server_url"]
		recipient_pin_state = None
	client.require_existing_identity()
	result = asyncio.run(client.send_message(
		recipient_identity,
		recipient_server_url,
		values["body"],
		sender_metadata,
		values.get("message_id"),
	))
	output = {
		"message_id": result.message_id,
		"recipient_trust_state": result.recipient_trust_state,
	}
	if recipient_pin_state is not None:
		output["recipient_pin_state"] = recipient_pin_state
	_write_json(output)
	return 0


def _cmd_receive(tokens: list[str]) -> int:
	values = _parse_key_values(
		tokens,
		scalar_keys=_CLIENT_KEYS | {"profile", "limit", "timeout"},
	)
	if "profile" in values:
		profile = _load_client_profile(Path(values["profile"]))
		_require_profile_clock_sync(profile)
		client_values = _client_values_from_profile(profile)
	else:
		_require_arguments(values, {"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir"})
		client_values = values
	client = _client_from_values(client_values)
	client.require_existing_identity()
	messages = asyncio.run(client.receive_messages(
		limit=_parse_int(values.get("limit", "1"), "limit", 1, 1000),
		timeout=_parse_float(values.get("timeout", "5"), "timeout", 0.0),
	))
	_write_json({"messages": [_message_to_dict(message) for message in messages]})
	return 0


def _cmd_doctor(tokens: list[str]) -> int:
	if tokens and tokens[0] == "server":
		values = _parse_key_values(tokens[1:], scalar_keys={"workspace"}, required_scalars={"workspace"})
		report = _doctor_server(Path(values["workspace"]))
	else:
		values = _parse_key_values(tokens, scalar_keys={"profile", "enrollment"})
		targets = [key for key in ("profile", "enrollment") if key in values]
		if len(targets) != 1:
			raise CliUsageError("doctor requires exactly one of profile=<path> or enrollment=<path>")
		if "profile" in values:
			report = _doctor_profile(Path(values["profile"]))
		else:
			report = _doctor_enrollment(Path(values["enrollment"]))
	_write_json(report)
	return 0 if report["status"] == "ok" else 1


_CLIENT_KEYS = {"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir", "ca_bundle"}


def _client_from_values(values: dict[str, Any]) -> EndpointClient:
	_require_arguments(values, {"client_ref", "home_server_url", "auth_token", "state_dir", "key_store_dir"})
	require(isinstance(values["auth_token"], str) and values["auth_token"] != "", "invalid_config", "auth_token is required")
	return EndpointClient(
		client_ref=values["client_ref"],
		home_server_url=_normalize_cli_url(values["home_server_url"], "home_server_url"),
		auth_token=values["auth_token"],
		state_dir=values["state_dir"],
		key_store_dir=values["key_store_dir"],
		verify_tls=_verify_tls_from_values(values),
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


def _write_json_file(path: str | Path, value: Any) -> None:
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


def _require_arguments(values: dict[str, Any], required: set[str]) -> None:
	missing = sorted(key for key in required if key not in values or values[key] == "")
	if missing:
		raise CliUsageError(f"missing required argument: {missing[0]}")


def _normalize_cli_url(value: str, field: str) -> str:
	require(isinstance(value, str) and value != "", "invalid_config", f"{field} is required")
	try:
		return normalize_server_url(value)
	except EndpointError as exc:
		raise EndpointError("invalid_config", f"{field} is invalid", detail=exc.message) from exc


def _require_url_port(server_url: str, port: int) -> None:
	parsed = urlparse(server_url)
	if parsed.port is not None:
		require(parsed.port == port, "invalid_config", "server_url port must match port")


def _verify_tls_from_values(values: dict[str, Any]) -> str | bool:
	raw = values.get("ca_bundle", True)
	if isinstance(raw, str):
		raw = _parse_optional_bool_or_string(raw, "ca_bundle")
	if isinstance(raw, str):
		path = Path(raw)
		require(path.exists(), "invalid_config", "ca_bundle could not be read")
		return str(path)
	require(isinstance(raw, bool), "invalid_config", "ca_bundle must be true, false, or a file path")
	return raw


def _validate_client_ref(value: str) -> str:
	require(isinstance(value, str) and value != "", "invalid_config", "client_ref is required")
	require(all(char.isalnum() or char in "._-" for char in value), "invalid_config", "client_ref may only contain letters, numbers, dot, underscore, or dash")
	return value


def _safe_file_stem(value: str) -> str:
	return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)


def _relative_path(path: Path, base: Path) -> str:
	try:
		return os.path.relpath(path, base)
	except ValueError:
		return str(path)


def _resolve_path(path: str | Path, base: Path) -> Path:
	item = Path(path)
	if item.is_absolute():
		return item
	return base / item


def _prepare_tls(workspace: Path, server_url: str, values: dict[str, str]) -> dict[str, Path]:
	tls_mode = values.get("tls", "dev")
	tls_dir = workspace / "tls"
	tls_dir.mkdir(parents=True, exist_ok=True)
	cert_path = tls_dir / "server.pem"
	key_path = tls_dir / "server.key"
	ca_path = tls_dir / "ca.pem"
	if tls_mode == "dev":
		_generate_dev_tls(server_url, cert_path, key_path, ca_path)
	elif tls_mode == "provided":
		for key in ("ssl_certfile", "ssl_keyfile", "ca_bundle"):
			require(values.get(key), "invalid_config", f"{key} is required when tls=provided")
		_copy_required_file(Path(values["ssl_certfile"]), cert_path, "ssl_certfile")
		_copy_required_file(Path(values["ssl_keyfile"]), key_path, "ssl_keyfile")
		_copy_required_file(Path(values["ca_bundle"]), ca_path, "ca_bundle")
	else:
		raise CliUsageError("tls must be dev or provided")
	return {"ssl_certfile": cert_path, "ssl_keyfile": key_path, "ca_bundle": ca_path}


def _generate_dev_tls(server_url: str, cert_path: Path, key_path: Path, ca_path: Path) -> None:
	try:
		import trustme
	except Exception as exc:
		raise EndpointError(
			"tls_unavailable",
			"dev TLS generation requires trustme; run: python -m pip install trustme or pass tls=provided ssl_certfile=... ssl_keyfile=... ca_bundle=...",
			detail=type(exc).__name__,
		) from exc
	hostname = urlparse(server_url).hostname
	require(hostname is not None and hostname != "", "invalid_config", "server_url host is required")
	names = [hostname]
	for extra in ("127.0.0.1", "localhost"):
		if extra not in names:
			names.append(extra)
	ca = trustme.CA()
	cert = ca.issue_cert(*names)
	cert.cert_chain_pems[0].write_to_path(cert_path)
	cert.private_key_pem.write_to_path(key_path)
	ca.cert_pem.write_to_path(ca_path)


def _copy_required_file(source: Path, target: Path, field: str) -> None:
	require(source.exists(), "invalid_config", f"{field} could not be read")
	shutil.copyfile(source, target)


def _server_config_document(
	*,
	server_url: str,
	state_dir: Path,
	hosted_identities: dict[str, dict[str, Any]],
	client_token_hashes: dict[str, str],
	ca_bundle: str | bool,
	allowed_ports: list[int],
	allow_private_networks: bool,
	rejected_policy: str,
	lease_seconds: int,
) -> dict[str, Any]:
	return {
		"protocol_version": PROTOCOL_VERSION,
		"server_url": server_url,
		"state_dir": str(state_dir),
		"hosted_identities": hosted_identities,
		"client_token_hashes": client_token_hashes,
		"ca_bundle": ca_bundle,
		"federation_policy": {
			"public_federation": True,
			"inbound_whitelist": [],
			"outbound_whitelist": [],
			"allow_private_networks": allow_private_networks,
			"allowed_ports": allowed_ports,
			"mode": "internal" if allow_private_networks else "public",
		},
		"lease_seconds": lease_seconds,
		"rejected_policy": rejected_policy,
		"debug_errors": False,
		"verify_hosted_identity_signatures": True,
	}


def _client_profile_document(
	*,
	profile_path: Path,
	client_ref: str,
	home_server_url: str,
	auth_token: str,
	state_dir: Path,
	key_store_dir: Path,
	ca_bundle: Path,
	identity_path: Path,
	contacts_dir: Path,
	metadata: dict[str, Any],
) -> dict[str, Any]:
	base = profile_path.parent
	return {
		"protocol_version": PROTOCOL_VERSION,
		"kind": "endpoint-client-profile",
		"client_ref": client_ref,
		"home_server_url": home_server_url,
		"auth_token": auth_token,
		"state_dir": _relative_path(state_dir, base),
		"key_store_dir": _relative_path(key_store_dir, base),
		"ca_bundle": _relative_path(ca_bundle, base),
		"identity_path": _relative_path(identity_path, base),
		"contacts_dir": _relative_path(contacts_dir, base),
		"metadata": metadata,
	}


def _load_client_profile(path: Path) -> dict[str, Any]:
	profile = _load_json_object(str(path), "profile")
	require(profile.get("protocol_version") == PROTOCOL_VERSION, "invalid_config", "profile protocol version is unsupported")
	require(profile.get("kind") == "endpoint-client-profile", "invalid_config", "profile kind is invalid")
	base = path.parent
	out = dict(profile)
	out["profile_path"] = str(path)
	out["home_server_url"] = _normalize_cli_url(profile["home_server_url"], "home_server_url")
	for key in ("state_dir", "key_store_dir", "identity_path", "contacts_dir"):
		require(isinstance(profile.get(key), str) and profile[key] != "", "invalid_config", f"profile {key} is required")
		out[key] = str(_resolve_path(profile[key], base))
	ca_bundle = profile.get("ca_bundle", True)
	if isinstance(ca_bundle, str):
		out["ca_bundle"] = str(_resolve_path(ca_bundle, base))
	else:
		out["ca_bundle"] = ca_bundle
	validate_metadata(out.get("metadata"))
	return out


def _client_values_from_profile(profile: dict[str, Any]) -> dict[str, Any]:
	return {
		"client_ref": profile["client_ref"],
		"home_server_url": profile["home_server_url"],
		"auth_token": profile["auth_token"],
		"state_dir": profile["state_dir"],
		"key_store_dir": profile["key_store_dir"],
		"ca_bundle": profile["ca_bundle"],
	}


def _write_contact(profile: dict[str, Any], server_url: str, client_ref: str, identity: dict[str, Any]) -> None:
	contacts_dir = Path(profile["contacts_dir"])
	contacts_dir.mkdir(parents=True, exist_ok=True)
	route_key = contact_route_key(server_url, client_ref)
	_write_json_file(contacts_dir / f"identity-{_route_key_hash(route_key)}.json", identity)


def _contact_index_path(profile: dict[str, Any]) -> Path:
	return Path(profile["contacts_dir"]) / "index.json"


def _route_key_hash(route_key: str) -> str:
	return hashlib.sha256(route_key.encode("utf-8")).hexdigest()


def _contact_path(profile: dict[str, Any], route_key: str) -> Path:
	return Path(profile["contacts_dir"]) / f"contact-{_route_key_hash(route_key)}.json"


def _load_contact_index(profile: dict[str, Any]) -> dict[str, dict[str, str]]:
	path = _contact_index_path(profile)
	if not path.exists():
		return {}
	value = parse_json_strict(path.read_text(encoding="utf-8"))
	require(isinstance(value, dict), "invalid_contact", "contact index must be a JSON object")
	index: dict[str, dict[str, str]] = {}
	for route_key, item in value.items():
		require(isinstance(route_key, str) and isinstance(item, dict), "invalid_contact", "contact index entry is invalid")
		require(set(item) == {"server_url", "client_ref", "endpoint_fingerprint"}, "invalid_contact", "contact index entry keys are invalid")
		server_url = _require_index_string(item, "server_url")
		client_ref = _require_index_string(item, "client_ref")
		endpoint_fingerprint = validate_endpoint_fingerprint(_require_index_string(item, "endpoint_fingerprint"))
		require(route_key == contact_route_key(server_url, client_ref), "invalid_contact", "contact index route key mismatch")
		index[route_key] = {
			"server_url": normalize_server_url(server_url),
			"client_ref": client_ref,
			"endpoint_fingerprint": endpoint_fingerprint,
		}
	return index


def _save_contact_index(profile: dict[str, Any], index: dict[str, dict[str, str]]) -> None:
	_write_json_file(_contact_index_path(profile), index)


def _load_contact_by_route(profile: dict[str, Any] | None, server_url: str, client_ref: str) -> dict[str, Any] | None:
	if profile is None:
		return None
	route_key = contact_route_key(server_url, client_ref)
	item = _load_contact_index(profile).get(route_key)
	if item is None:
		return None
	path = _contact_path(profile, route_key)
	contact = normalize_contact(_load_json_object(str(path), "contact"))
	require(contact_route_key(contact["server_url"], contact["client_ref"]) == route_key, "invalid_contact", "stored contact route mismatch")
	require(contact["endpoint_fingerprint"] == item["endpoint_fingerprint"], "invalid_contact", "stored contact fingerprint mismatch")
	return contact


def _contacts_for_client_ref(profile: dict[str, Any], client_ref: str) -> list[dict[str, str]]:
	return [item for item in _load_contact_index(profile).values() if item["client_ref"] == client_ref]


def _remember_contact(profile: dict[str, Any], client: EndpointClient, contact: dict[str, Any]) -> tuple[dict[str, Any], str]:
	contact = client.validate_contact_pin(contact)
	route_key = contact_route_key(contact["server_url"], contact["client_ref"])
	contacts_dir = Path(profile["contacts_dir"])
	contacts_dir.mkdir(parents=True, exist_ok=True)
	contact_path = _contact_path(profile, route_key)
	old_contact_bytes = contact_path.read_bytes() if contact_path.exists() else None
	_write_json_file(contact_path, contact)
	index = _load_contact_index(profile)
	old_index = dict(index)
	index[route_key] = {
		"server_url": contact["server_url"],
		"client_ref": contact["client_ref"],
		"endpoint_fingerprint": contact["endpoint_fingerprint"],
	}
	_save_contact_index(profile, index)
	try:
		contact = client.import_contact_pin(contact)
	except Exception:
		_rollback_contact_import(profile, contact_path, old_contact_bytes, old_index)
		raise
	return contact, route_key


def _rollback_contact_import(profile: dict[str, Any], contact_path: Path, old_contact_bytes: bytes | None, old_index: dict[str, dict[str, str]]) -> None:
	try:
		if old_contact_bytes is None:
			contact_path.unlink(missing_ok=True)
		else:
			contact_path.write_bytes(old_contact_bytes)
		index_path = _contact_index_path(profile)
		if old_index:
			_save_contact_index(profile, old_index)
		else:
			index_path.unlink(missing_ok=True)
	except Exception:
		pass


def _require_index_string(item: dict[str, Any], key: str) -> str:
	value = item.get(key)
	require(isinstance(value, str) and value != "", "invalid_contact", f"contact index {key} is invalid")
	return value


def _load_workspace(workspace: Path) -> dict[str, Any]:
	doc = _load_json_object(str(workspace / "workspace.json"), "workspace")
	require(doc.get("protocol_version") == PROTOCOL_VERSION, "invalid_config", "workspace protocol version is unsupported")
	require(doc.get("kind") == "endpoint-demo-host-workspace", "invalid_config", "workspace kind is invalid")
	return doc


def _write_invite_zip(path: Path, invite: dict[str, Any], ca_path: Path) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		archive.writestr("invite.json", canonical_json_bytes(invite))
		archive.write(ca_path, "ca.pem")


def _read_invite_zip(path: Path) -> tuple[dict[str, Any], bytes]:
	try:
		with zipfile.ZipFile(path) as archive:
			invite = parse_json_strict(archive.read("invite.json"))
			ca_bytes = archive.read("ca.pem")
	except EndpointError:
		raise
	except Exception as exc:
		raise EndpointError("invalid_config", "invite could not be read", detail=type(exc).__name__) from exc
	require(isinstance(invite, dict), "invalid_config", "invite must be a JSON object")
	require(invite.get("protocol_version") == PROTOCOL_VERSION, "invalid_config", "invite protocol version is unsupported")
	require(invite.get("kind") == "endpoint-demo-invite", "invalid_config", "invite kind is invalid")
	for field in ("server_url", "client_ref", "auth_token"):
		require(isinstance(invite.get(field), str) and invite[field] != "", "invalid_config", f"invite {field} is required")
	require(b"PRIVATE KEY BLOCK" not in ca_bytes, "invalid_config", "invite CA bundle is invalid")
	return invite, ca_bytes


def _write_enrollment_zip(path: Path, enrollment: dict[str, Any], identity: dict[str, Any]) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
		archive.writestr("enrollment.json", canonical_json_bytes(enrollment))
		archive.writestr("identity.json", canonical_json_bytes(identity))


def _read_enrollment_zip(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
	require(path.exists(), "invalid_config", "enrollment file could not be read")
	try:
		with zipfile.ZipFile(path) as archive:
			enrollment = parse_json_strict(archive.read("enrollment.json"))
			identity = parse_json_strict(archive.read("identity.json"))
	except EndpointError:
		raise
	except KeyError as exc:
		raise EndpointError("invalid_config", "enrollment zip is missing required files", detail=str(exc)) from exc
	except zipfile.BadZipFile as exc:
		raise EndpointError("invalid_config", "enrollment zip is invalid", detail=type(exc).__name__) from exc
	except Exception as exc:
		raise EndpointError("invalid_config", "enrollment zip could not be read", detail=type(exc).__name__) from exc
	require(isinstance(enrollment, dict), "invalid_config", "enrollment must be a JSON object")
	require(enrollment.get("protocol_version") == PROTOCOL_VERSION, "invalid_config", "enrollment protocol version is unsupported")
	require(enrollment.get("kind") == "endpoint-demo-enrollment", "invalid_config", "enrollment kind is invalid")
	if "created_at_utc" in enrollment:
		_parse_utc_iso(str(enrollment["created_at_utc"]), "enrollment created_at_utc")
	validate_identity_envelope(identity)
	return enrollment, identity


def _verify_identity_signature(identity: dict[str, Any]) -> None:
	validate_identity_envelope(identity)
	computed = endpoint_fingerprint(identity["public_key_armored"])
	require(computed == identity["endpoint_fingerprint"], "invalid_identity_signature", "identity fingerprint does not match public key")
	payload = canonical_json_bytes(identity_signature_payload(identity))
	try:
		verify_detached(identity["public_key_armored"], payload, identity["identity_signature"])
	except EndpointError as exc:
		raise EndpointError("invalid_identity_signature", "identity signature does not verify", detail=exc.detail, hint=IDENTITY_SIGNATURE_HINT) from exc


def _check_enrollment_bundle(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
	enrollment, identity = _read_enrollment_zip(path)
	require(identity["client_ref"] == enrollment["client_ref"], "invalid_config", "enrollment identity client_ref mismatch")
	_verify_identity_signature(identity)
	return enrollment, identity


def _doctor_profile(profile_path: Path) -> dict[str, Any]:
	checks: list[dict[str, Any]] = []
	profile: dict[str, Any] | None = None
	client: EndpointClient | None = None
	try:
		profile = _load_client_profile(profile_path)
		_add_check(checks, "profile_readable", True, str(profile_path))
	except Exception as exc:
		_add_check(checks, "profile_readable", False, _safe_exception_message(exc))
	if profile is not None:
		ca_bundle = profile.get("ca_bundle")
		_add_check(checks, "ca_bundle_readable", not isinstance(ca_bundle, str) or Path(ca_bundle).exists(), str(ca_bundle))
		try:
			client = _client_from_values(_client_values_from_profile(profile))
			fingerprint = client.require_existing_identity()
			_add_check(checks, "key_store_initialized", True, fingerprint)
		except Exception as exc:
			_add_check(checks, "key_store_initialized", False, _safe_exception_message(exc))
		try:
			identity = _load_json_object(profile["identity_path"], "profile identity")
			_verify_identity_signature(identity)
			if client is not None:
				public_key = client.openpgp.export_public_key(client.require_existing_identity())
				require(endpoint_fingerprint(public_key) == identity["endpoint_fingerprint"], "invalid_config", "profile identity does not match local key store")
			_add_check(checks, "identity_matches_key_store", True, identity["endpoint_fingerprint"])
		except Exception as exc:
			_add_check(checks, "identity_matches_key_store", False, _safe_exception_message(exc))
		try:
			response = httpx.get(f"{profile['home_server_url']}/v1/health", verify=httpx_verify_config(_verify_tls_from_values(profile)), timeout=2.0, follow_redirects=False)
		except Exception as exc:
			_add_check(checks, "server_reachable", False, _safe_exception_message(exc))
		else:
			_add_check(checks, "server_reachable", response.status_code == 200, f"status={response.status_code}")
			if response.status_code == 200:
				try:
					health = parse_json_strict(response.text)
					require(isinstance(health, dict), "invalid_envelope", "health response must be an object")
					server_time = health.get("server_time_utc")
					require(isinstance(server_time, str) and server_time != "", "invalid_envelope", "health response is missing server_time_utc")
					_add_clock_skew_check(checks, _parse_utc_iso(server_time, "server_time_utc"), "server")
				except Exception as exc:
					_add_check(checks, "clock_skew_seconds", False, _safe_exception_message(exc))
		if client is not None:
			try:
				result = asyncio.run(client.discover(profile["home_server_url"], profile["client_ref"]))
				_add_check(checks, "token_auth_and_hosted_identity", result.identity["endpoint_fingerprint"] == _load_json_object(profile["identity_path"], "profile identity")["endpoint_fingerprint"], result.identity["endpoint_fingerprint"])
			except Exception as exc:
				_add_check(checks, "token_auth_and_hosted_identity", False, _safe_exception_message(exc))
	return _doctor_report(checks)


def _doctor_enrollment(path: Path) -> dict[str, Any]:
	checks: list[dict[str, Any]] = []
	try:
		enrollment, identity = _read_enrollment_zip(path)
		_add_check(checks, "enrollment_readable", True, str(path))
	except Exception as exc:
		_add_check(checks, "enrollment_readable", False, _safe_exception_message(exc))
		return _doctor_report(checks)
	client_ref = enrollment.get("client_ref")
	fingerprint = identity.get("endpoint_fingerprint")
	_add_check(
		checks,
		"enrollment_identity",
		identity.get("client_ref") == client_ref,
		str(client_ref),
		client_ref=client_ref,
		endpoint_fingerprint=fingerprint,
	)
	created_at = enrollment.get("created_at_utc")
	created_skew: int | None = None
	if isinstance(created_at, str) and created_at:
		try:
			created_time = _parse_utc_iso(created_at, "created_at_utc")
			created_skew = _add_clock_skew_check(checks, created_time, "enrollment")
		except Exception as exc:
			_add_check(checks, "enrollment_created_at_utc", False, _safe_exception_message(exc))
	else:
		_add_check(checks, "enrollment_created_at_utc", False, "created_at_utc is missing")
	try:
		_verify_identity_signature(identity)
		_add_check(checks, "identity_signature", True, str(fingerprint))
	except Exception as exc:
		message = _safe_exception_message(exc)
		if created_skew is not None and abs(created_skew) > CLOCK_SKEW_LIMIT_SECONDS:
			message = f"{message}; clock skew is a likely cause"
		_add_check(checks, "identity_signature", False, message, hint=IDENTITY_SIGNATURE_HINT)
	return _doctor_report(checks)


def _doctor_server(workspace: Path) -> dict[str, Any]:
	checks: list[dict[str, Any]] = []
	try:
		workspace_doc = _load_workspace(workspace)
		_add_check(checks, "workspace_readable", True, str(workspace))
	except Exception as exc:
		_add_check(checks, "workspace_readable", False, _safe_exception_message(exc))
		return _doctor_report(checks)
	for key in ("ssl_certfile", "ssl_keyfile", "ca_bundle"):
		path = _resolve_path(workspace_doc[key], workspace)
		_add_check(checks, f"{key}_readable", path.exists(), str(path))
	try:
		config_path = _resolve_path(workspace_doc["server_config"], workspace)
		config = load_server_config(config_path)
		_add_check(checks, "server_config_readable", True, str(config_path))
	except Exception as exc:
		_add_check(checks, "server_config_readable", False, _safe_exception_message(exc))
		return _doctor_report(checks)
	parsed = urlparse(config.server_url)
	url_port = parsed.port or 443
	_add_check(checks, "configured_port_matches_run_port", url_port == workspace_doc["port"], f"url_port={url_port} run_port={workspace_doc['port']}")
	for client_ref, verifier in config.client_token_hashes.items():
		try:
			validate_client_token_hash(verifier)
			_add_check(checks, f"token_hash_{client_ref}", True, "ok")
		except Exception as exc:
			_add_check(checks, f"token_hash_{client_ref}", False, _safe_exception_message(exc))
	for client_ref, identity in config.hosted_identities.items():
		try:
			require(identity["client_ref"] == client_ref, "invalid_config", "hosted identity client_ref mismatch")
			_verify_identity_signature(identity)
			_add_check(checks, f"hosted_identity_{client_ref}", True, identity["endpoint_fingerprint"])
		except Exception as exc:
			_add_check(checks, f"hosted_identity_{client_ref}", False, _safe_exception_message(exc))
	log_path = config.state_dir / "logs" / "structured.jsonl"
	_add_check(checks, "structured_log", True, str(log_path) if log_path.exists() else "not created yet")
	return _doctor_report(checks)


def _add_check(checks: list[dict[str, Any]], name: str, ok: bool, message: str, **fields: Any) -> None:
	record = {"name": name, "ok": ok, "message": message}
	record.update({key: value for key, value in fields.items() if value is not None})
	checks.append(record)


def _add_clock_skew_check(checks: list[dict[str, Any]], reference_time: datetime, label: str) -> int:
	local_time = _utc_now()
	skew = _clock_skew_seconds(reference_time, local_time)
	ok = abs(skew) <= CLOCK_SKEW_LIMIT_SECONDS
	_add_check(
		checks,
		"clock_skew_seconds",
		ok,
		_clock_skew_message(skew, label),
		clock_skew_seconds=skew,
		local_time_utc=_format_utc(local_time),
		reference_time_utc=_format_utc(reference_time),
	)
	return skew


def _require_profile_clock_sync(profile: dict[str, Any]) -> None:
	server_time = _fetch_server_utc_time(profile)
	skew = _clock_skew_seconds(server_time, _utc_now())
	if abs(skew) > CLOCK_SKEW_LIMIT_SECONDS:
		raise EndpointError("clock_skew", _clock_skew_message(skew, "server"), hint=CLOCK_SKEW_HINT)


def _fetch_server_utc_time(profile: dict[str, Any]) -> datetime:
	try:
		response = httpx.get(f"{profile['home_server_url']}/v1/health", verify=httpx_verify_config(_verify_tls_from_values(profile)), timeout=2.0, follow_redirects=False)
	except Exception as exc:
		raise EndpointError("server_unreachable", "server health check failed", detail=type(exc).__name__) from exc
	require(response.status_code == 200, "server_unreachable", "server health check failed", detail=f"status={response.status_code}")
	health = parse_json_strict(response.text)
	require(isinstance(health, dict), "invalid_envelope", "health response must be an object")
	server_time = health.get("server_time_utc")
	require(isinstance(server_time, str) and server_time != "", "invalid_envelope", "health response is missing server_time_utc")
	return _parse_utc_iso(server_time, "server_time_utc")


def _clock_skew_seconds(reference_time: datetime, local_time: datetime) -> int:
	return int(round((local_time - reference_time).total_seconds()))


def _clock_skew_message(skew_seconds: int, label: str) -> str:
	if skew_seconds == 0:
		return f"local clock matches {label} UTC time"
	direction = "ahead of" if skew_seconds > 0 else "behind"
	return f"local clock is {abs(skew_seconds)} seconds {direction} {label} UTC time"


def _doctor_report(checks: list[dict[str, Any]]) -> dict[str, Any]:
	return {"status": "ok" if all(check["ok"] for check in checks) else "failed", "checks": checks}


def _safe_exception_message(exc: Exception) -> str:
	if isinstance(exc, EndpointError):
		return f"{exc.code}: {exc.message}"
	return type(exc).__name__


def _utc_now() -> datetime:
	return datetime.now(UTC).replace(microsecond=0)


def _format_utc(value: datetime) -> str:
	return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_utc_iso(value: str, field: str) -> datetime:
	try:
		parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
	except Exception as exc:
		raise EndpointError("invalid_envelope", f"{field} must be an ISO UTC timestamp", detail=type(exc).__name__) from exc
	require(parsed.tzinfo is not None, "invalid_envelope", f"{field} must include UTC offset")
	return parsed.astimezone(UTC).replace(microsecond=0)


if __name__ == "__main__":
	raise SystemExit(main())
