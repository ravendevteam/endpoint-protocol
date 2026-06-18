from __future__ import annotations

import socket
import threading
import time
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
import trustme
import uvicorn

from endpoint import cli
from endpoint.config import load_server_config
from endpoint.credentials import generate_client_token, hash_client_token, validate_client_token_strength, verify_client_token
from endpoint.errors import EndpointError
from endpoint.protocol import canonical_json_bytes, parse_json_strict
from endpoint.server_core import create_app
from endpoint.transport import httpx_verify_config


def test_key_value_parser_accepts_lists_maps_booleans_integers_and_json() -> None:
	values = cli._parse_key_values(
		[
			"name=server",
			"enabled=true",
			"allowed_port=8443",
			"allowed_port=9443",
			"hosted_identity.bob=bob.identity.json",
			"client_token_hash.bob=pbkdf2_sha256:hash",
			"metadata_json={\"username\":\"bob\"}",
		],
		scalar_keys={"name", "enabled", "metadata_json"},
		list_keys={"allowed_port"},
		map_prefixes={"hosted_identity", "client_token_hash"},
		required_scalars={"name"},
		required_maps={"hosted_identity", "client_token_hash"},
	)
	assert values["name"] == "server"
	assert cli._parse_bool(values["enabled"], "enabled") is True
	assert [cli._parse_int(value, "allowed_port", 1, 65535) for value in values["allowed_port"]] == [8443, 9443]
	assert values["hosted_identity"] == {"bob": "bob.identity.json"}
	assert values["client_token_hash"] == {"bob": "pbkdf2_sha256:hash"}
	assert cli._metadata_from_values(values) == {"username": "bob"}


@pytest.mark.parametrize(
	"tokens, expected",
	[
		(["name=one", "name=two"], "duplicate argument: name"),
		(["unknown=value"], "unknown argument: unknown"),
		(["not-key-value"], "expected key=value argument"),
		(["hosted_identity.=identity.json"], "missing map key"),
	],
)
def test_key_value_parser_rejects_bad_shapes(tokens: list[str], expected: str) -> None:
	with pytest.raises(cli.CliUsageError) as exc:
		cli._parse_key_values(tokens, scalar_keys={"name"}, map_prefixes={"hosted_identity"})
	assert expected in str(exc.value)


def test_parser_rejects_missing_required_invalid_bool_invalid_int_and_bad_json() -> None:
	with pytest.raises(cli.CliUsageError) as missing_exc:
		cli._parse_key_values([], scalar_keys={"name"}, required_scalars={"name"})
	assert "missing required argument: name" in str(missing_exc.value)
	with pytest.raises(cli.CliUsageError):
		cli._parse_bool("yes", "enabled")
	with pytest.raises(cli.CliUsageError):
		cli._parse_int("eight", "allowed_port", 1, 65535)
	with pytest.raises(EndpointError):
		cli._metadata_from_values({"metadata_json": "{\"username\":"})


def test_token_commands_generate_and_hash_client_tokens(capsys: pytest.CaptureFixture[str]) -> None:
	assert cli.main(["token", "generate"]) == 0
	token_output = parse_json_strict(capsys.readouterr().out)
	token = token_output["token"]
	validate_client_token_strength(token)
	assert cli.main(["token", "hash", f"token={token}"]) == 0
	hash_output = parse_json_strict(capsys.readouterr().out)
	assert verify_client_token(token, hash_output["client_token_hash"])


def test_endpoint_error_safe_body_includes_hint_without_debug_detail() -> None:
	error = EndpointError("invalid_identity_signature", "identity signature does not verify", detail="SignatureInvalid: no valid signature", hint="Sync clocks and retry.")
	safe = error.safe_body()
	assert safe["error"] == {
		"code": "invalid_identity_signature",
		"message": "identity signature does not verify",
		"hint": "Sync clocks and retry.",
	}
	debug = error.safe_body(debug=True)
	assert debug["error"]["detail"] == "SignatureInvalid: no valid signature"


def test_cli_reports_usage_and_endpoint_errors_safely(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
	assert cli.main(["token", "hash"]) == 2
	usage = capsys.readouterr()
	assert "missing required argument: token" in usage.err
	assert cli.main([
		"send",
		"client_ref=alice",
		"home_server_url=https://127.0.0.1:443",
		"auth_token=unused",
		f"state_dir={tmp_path / 'state'}",
		f"key_store_dir={tmp_path / 'keys'}",
		"recipient_identity=missing.identity.json",
		"recipient_server_url=https://127.0.0.1:443",
		"body=hello",
	]) == 1
	error_output = parse_json_strict(capsys.readouterr().err)
	assert error_output["error"]["code"] == "crypto_failed"
	assert "detail" not in error_output["error"]


def test_identity_export_and_server_config_commands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
	token = generate_client_token()
	token_hash = hash_client_token(token)
	identity_path = tmp_path / "alice.identity.json"
	config_path = tmp_path / "server.json"
	assert cli.main([
		"identity",
		"export",
		"client_ref=alice",
		"home_server_url=https://example.com",
		f"auth_token={token}",
		f"state_dir={tmp_path / 'alice-state'}",
		f"key_store_dir={tmp_path / 'alice-keys'}",
		"name=Alice",
		"email=alice@example.test",
		"metadata_json={\"username\":\"alice\"}",
		f"out={identity_path}",
	]) == 0
	identity = parse_json_strict(capsys.readouterr().out)
	assert identity["client_ref"] == "alice"
	assert identity_path.exists()
	assert cli.main([
		"server",
		"init-config",
		"server_url=https://example.com",
		f"state_dir={tmp_path / 'server-state'}",
		f"hosted_identity.alice={identity_path}",
		f"client_token_hash.alice={token_hash}",
		"allowed_port=443",
		f"out={config_path}",
	]) == 0
	config = parse_json_strict(capsys.readouterr().out)
	assert config["hosted_identities"]["alice"]["endpoint_fingerprint"] == identity["endpoint_fingerprint"]
	assert load_server_config(config_path).server_url == "https://example.com"
	assert cli.main(["server", "validate-config", f"config={config_path}"]) == 0
	assert parse_json_strict(capsys.readouterr().out) == {"config": str(config_path), "status": "ok"}


def test_identity_export_reuses_existing_key_store(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
	token = generate_client_token()
	identity_path = tmp_path / "alice.identity.json"
	args = [
		"identity",
		"export",
		"client_ref=alice",
		"home_server_url=https://example.com",
		f"auth_token={token}",
		f"state_dir={tmp_path / 'state'}",
		f"key_store_dir={tmp_path / 'keys'}",
		"name=Alice",
		"email=alice@example.test",
		f"out={identity_path}",
	]
	assert cli.main(args) == 0
	first = parse_json_strict(capsys.readouterr().out)
	assert cli.main(args) == 0
	second = parse_json_strict(capsys.readouterr().out)
	assert second["endpoint_fingerprint"] == first["endpoint_fingerprint"]
	assert parse_json_strict(identity_path.read_text(encoding="utf-8"))["endpoint_fingerprint"] == first["endpoint_fingerprint"]


def test_setup_bundles_do_not_include_private_keys_and_profiles_resolve_paths(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
	host = tmp_path / "host"
	guest = tmp_path / "guest"
	invite = tmp_path / "bob.endpoint-invite.zip"
	enrollment = tmp_path / "bob.endpoint-enrollment.zip"
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	assert cli.main([
		"setup",
		"host-init",
		f"workspace={host}",
		f"server_url={url}",
		"bind_host=127.0.0.1",
		f"port={port}",
		"owner_ref=alice",
		"owner_name=Alice",
	]) == 0
	capsys.readouterr()
	assert cli.main(["setup", "invite", f"workspace={host}", "client_ref=bob", f"out={invite}"]) == 0
	capsys.readouterr()
	assert_zip_has_no_private_key(invite)
	assert cli.main(["setup", "join", f"invite={invite}", f"workspace={guest}", "name=Bob", f"out={enrollment}"]) == 0
	join_output = parse_json_strict(capsys.readouterr().out)
	assert join_output["profile"] == str(guest / "profile.json")
	assert_zip_has_no_private_key(enrollment)
	assert cli.main(["doctor", f"enrollment={enrollment}"]) == 0
	enrollment_report = parse_json_strict(capsys.readouterr().out)
	enrollment_checks = {check["name"]: check for check in enrollment_report["checks"]}
	assert enrollment_checks["enrollment_readable"]["ok"] is True
	assert enrollment_checks["identity_signature"]["ok"] is True
	profile = cli._load_client_profile(guest / "profile.json")
	assert Path(profile["ca_bundle"]) == guest / "ca.pem"
	assert Path(profile["key_store_dir"]) == guest / "keys"
	assert Path(profile["state_dir"]) == guest / "state"
	assert cli.main(["setup", "enroll", f"workspace={host}", f"enrollment={enrollment}"]) == 0
	enroll_output = parse_json_strict(capsys.readouterr().out)
	assert enroll_output["client_ref"] == "bob"
	config = load_server_config(host / "server.json")
	assert set(config.hosted_identities) == {"alice", "bob"}
	assert set(config.client_token_hashes) == {"alice", "bob"}
	assert cli.main(["setup", "enroll", f"workspace={host}", f"enrollment={enrollment}"]) == 1
	missing_pending = parse_json_strict(capsys.readouterr().err)
	assert missing_pending["error"]["message"] == "pending invite was not found for this enrollment"


def test_doctor_enrollment_reports_tampered_signature_with_safe_hint(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
	host = tmp_path / "host"
	guest = tmp_path / "guest"
	invite = tmp_path / "bob.endpoint-invite.zip"
	enrollment = tmp_path / "bob.endpoint-enrollment.zip"
	tampered = tmp_path / "bob.tampered-enrollment.zip"
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	assert cli.main([
		"setup",
		"host-init",
		f"workspace={host}",
		f"server_url={url}",
		"bind_host=127.0.0.1",
		f"port={port}",
		"owner_ref=alice",
		"owner_name=Alice",
	]) == 0
	capsys.readouterr()
	assert cli.main(["setup", "invite", f"workspace={host}", "client_ref=bob", f"out={invite}"]) == 0
	capsys.readouterr()
	assert cli.main(["setup", "join", f"invite={invite}", f"workspace={guest}", "name=Bob", f"out={enrollment}"]) == 0
	capsys.readouterr()
	write_tampered_enrollment(enrollment, tampered)
	assert cli.main(["doctor", f"enrollment={tampered}"]) == 1
	report = parse_json_strict(capsys.readouterr().out)
	checks = {check["name"]: check for check in report["checks"]}
	assert checks["identity_signature"]["ok"] is False
	assert checks["identity_signature"]["hint"] == cli.IDENTITY_SIGNATURE_HINT
	assert "PRIVATE KEY" not in checks["identity_signature"]["message"]


def test_health_includes_utc_time_and_doctor_reports_clock_skew(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
	host = tmp_path / "host"
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	assert cli.main([
		"setup",
		"host-init",
		f"workspace={host}",
		f"server_url={url}",
		"bind_host=127.0.0.1",
		f"port={port}",
		"owner_ref=alice",
		"owner_name=Alice",
	]) == 0
	capsys.readouterr()
	app = create_app(load_server_config(host / "server.json"))
	profile = host / "clients" / "alice" / "profile.json"
	with RunningServer(app, port, host / "tls" / "server.pem", host / "tls" / "server.key", host / "tls" / "ca.pem"):
		response = httpx.get(f"{url}/v1/health", verify=httpx_verify_config(str(host / "tls" / "ca.pem")), timeout=2.0)
		body = response.json()
		assert body["status"] == "ok"
		assert cli._parse_utc_iso(body["server_time_utc"], "server_time_utc").tzinfo is not None
		monkeypatch.setattr(cli, "_utc_now", lambda: datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5))
		assert cli.main(["doctor", f"profile={profile}"]) == 1
		report = parse_json_strict(capsys.readouterr().out)
		checks = [check for check in report["checks"] if check["name"] == "clock_skew_seconds"]
		assert checks
		assert checks[0]["ok"] is False
		assert checks[0]["clock_skew_seconds"] >= 250


def test_doctor_profile_detects_fake_future_health_time(tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch) -> None:
	profile_path = tmp_path / "profile.json"
	local_now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
	cli._write_json_file(profile_path, {
		"protocol_version": "endpoint-poc-1",
		"kind": "endpoint-client-profile",
		"client_ref": "bob",
		"home_server_url": "https://127.0.0.1:8443",
		"auth_token": generate_client_token(),
		"state_dir": "state",
		"key_store_dir": "keys",
		"ca_bundle": False,
		"identity_path": "identity.json",
		"contacts_dir": "contacts",
		"metadata": {"username": "bob"},
	})
	class FakeResponse:
		status_code = 200
		text = canonical_json_bytes({
			"status": "ok",
			"server_time_utc": "2026-01-01T12:05:00Z",
		}).decode("utf-8")

	monkeypatch.setattr(cli, "_utc_now", lambda: local_now)
	monkeypatch.setattr(cli.httpx, "get", lambda *args, **kwargs: FakeResponse())
	assert cli.main(["doctor", f"profile={profile_path}"]) == 1
	report = parse_json_strict(capsys.readouterr().out)
	checks = [check for check in report["checks"] if check["name"] == "clock_skew_seconds"]
	assert checks
	assert checks[0]["clock_skew_seconds"] == -300
	assert checks[0]["ok"] is False
	assert cli.main(["receive", f"profile={profile_path}"]) == 1
	error = parse_json_strict(capsys.readouterr().err)
	assert error["error"]["code"] == "clock_skew"
	assert error["error"]["hint"] == cli.CLOCK_SKEW_HINT


def test_doctor_reports_common_profile_failures(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
	profile_path = tmp_path / "profile.json"
	cli._write_json_file(profile_path, {
		"protocol_version": "endpoint-poc-1",
		"kind": "endpoint-client-profile",
		"client_ref": "bob",
		"home_server_url": "https://127.0.0.1:8443",
		"auth_token": generate_client_token(),
		"state_dir": "state",
		"key_store_dir": "keys",
		"ca_bundle": "missing-ca.pem",
		"identity_path": "identity.json",
		"contacts_dir": "contacts",
		"metadata": {"username": "bob"},
	})
	assert cli.main(["doctor", f"profile={profile_path}"]) == 1
	report = parse_json_strict(capsys.readouterr().out)
	assert report["status"] == "failed"
	checks = {check["name"]: check for check in report["checks"]}
	assert checks["ca_bundle_readable"]["ok"] is False
	assert checks["key_store_initialized"]["ok"] is False


def test_cli_driven_same_server_exchange_drains_queue_without_plaintext(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	alice_token = generate_client_token()
	bob_token = generate_client_token()
	alice_identity = tmp_path / "alice.identity.json"
	bob_identity = tmp_path / "bob.identity.json"
	server_config = tmp_path / "server.json"
	server_state = tmp_path / "server-state"
	body = "cli plaintext should not be stored on server"
	assert cli.main([
		"identity",
		"export",
		"client_ref=alice",
		f"home_server_url={url}",
		f"auth_token={alice_token}",
		f"state_dir={tmp_path / 'alice-state'}",
		f"key_store_dir={tmp_path / 'alice-keys'}",
		f"ca_bundle={ca_path}",
		"name=Alice",
		"email=alice@example.test",
		"metadata_json={\"username\":\"alice\"}",
		f"out={alice_identity}",
	]) == 0
	capsys.readouterr()
	assert cli.main([
		"identity",
		"export",
		"client_ref=bob",
		f"home_server_url={url}",
		f"auth_token={bob_token}",
		f"state_dir={tmp_path / 'bob-state'}",
		f"key_store_dir={tmp_path / 'bob-keys'}",
		f"ca_bundle={ca_path}",
		"name=Bob",
		"email=bob@example.test",
		"metadata_json={\"username\":\"bob\"}",
		f"out={bob_identity}",
	]) == 0
	capsys.readouterr()
	assert cli.main([
		"server",
		"init-config",
		f"server_url={url}",
		f"state_dir={server_state}",
		f"hosted_identity.alice={alice_identity}",
		f"hosted_identity.bob={bob_identity}",
		f"client_token_hash.alice={hash_client_token(alice_token)}",
		f"client_token_hash.bob={hash_client_token(bob_token)}",
		f"ca_bundle={ca_path}",
		f"allowed_port={port}",
		"allow_private_networks=true",
		f"out={server_config}",
	]) == 0
	capsys.readouterr()
	app = create_app(load_server_config(server_config))
	with RunningServer(app, port, cert_path, key_path, ca_path):
		assert cli.main([
			"send",
			"client_ref=alice",
			f"home_server_url={url}",
			f"auth_token={alice_token}",
			f"state_dir={tmp_path / 'alice-state'}",
			f"key_store_dir={tmp_path / 'alice-keys'}",
			f"ca_bundle={ca_path}",
			f"recipient_identity={bob_identity}",
			f"recipient_server_url={url}",
			f"body={body}",
			"metadata_json={\"username\":\"alice\"}",
		]) == 0
		send_output = parse_json_strict(capsys.readouterr().out)
		assert isinstance(send_output["message_id"], str)
		assert app.state.endpoint.queue.count_active("bob") == 1
		assert cli.main([
			"receive",
			"client_ref=bob",
			f"home_server_url={url}",
			f"auth_token={bob_token}",
			f"state_dir={tmp_path / 'bob-state'}",
			f"key_store_dir={tmp_path / 'bob-keys'}",
			f"ca_bundle={ca_path}",
			"limit=1",
			"timeout=5",
		]) == 0
		receive_output = parse_json_strict(capsys.readouterr().out)
		assert [message["body"] for message in receive_output["messages"]] == [body]
		assert app.state.endpoint.queue.count_active("bob") == 0
	assert_plaintext_absent(server_state, body)


def test_setup_profile_driven_same_server_exchange_round_trip(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
	host = tmp_path / "host"
	guest = tmp_path / "guest"
	invite = tmp_path / "bob.endpoint-invite.zip"
	enrollment = tmp_path / "bob.endpoint-enrollment.zip"
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	assert cli.main([
		"setup",
		"host-init",
		f"workspace={host}",
		f"server_url={url}",
		"bind_host=127.0.0.1",
		f"port={port}",
		"owner_ref=alice",
		"owner_name=Alice",
	]) == 0
	capsys.readouterr()
	assert cli.main(["setup", "invite", f"workspace={host}", "client_ref=bob", f"out={invite}"]) == 0
	capsys.readouterr()
	assert cli.main(["setup", "join", f"invite={invite}", f"workspace={guest}", "name=Bob", f"out={enrollment}"]) == 0
	capsys.readouterr()
	assert cli.main(["setup", "enroll", f"workspace={host}", f"enrollment={enrollment}"]) == 0
	capsys.readouterr()
	app = create_app(load_server_config(host / "server.json"))
	body_ab = "profile-driven hello bob"
	body_ba = "profile-driven hello alice"
	with RunningServer(app, port, host / "tls" / "server.pem", host / "tls" / "server.key", host / "tls" / "ca.pem"):
		assert cli.main(["send", f"profile={host / 'clients' / 'alice' / 'profile.json'}", "to=bob", f"body={body_ab}"]) == 0
		send_ab = parse_json_strict(capsys.readouterr().out)
		assert isinstance(send_ab["message_id"], str)
		assert app.state.endpoint.queue.count_active("bob") == 1
		assert cli.main(["receive", f"profile={guest / 'profile.json'}", "limit=1", "timeout=5"]) == 0
		receive_b = parse_json_strict(capsys.readouterr().out)
		assert [message["body"] for message in receive_b["messages"]] == [body_ab]
		assert app.state.endpoint.queue.count_active("bob") == 0
		assert cli.main(["send", f"profile={guest / 'profile.json'}", "to=alice", f"body={body_ba}"]) == 0
		send_ba = parse_json_strict(capsys.readouterr().out)
		assert isinstance(send_ba["message_id"], str)
		assert app.state.endpoint.queue.count_active("alice") == 1
		assert cli.main(["receive", f"profile={host / 'clients' / 'alice' / 'profile.json'}", "limit=1", "timeout=5"]) == 0
		receive_a = parse_json_strict(capsys.readouterr().out)
		assert [message["body"] for message in receive_a["messages"]] == [body_ba]
		assert app.state.endpoint.queue.count_active("alice") == 0
	assert_plaintext_absent(host / "server-state", body_ab)
	assert_plaintext_absent(host / "server-state", body_ba)


def free_port() -> int:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		sock.bind(("127.0.0.1", 0))
		return sock.getsockname()[1]


def make_tls(tmp_path: Path) -> tuple[Path, Path, Path]:
	ca = trustme.CA()
	cert = ca.issue_cert("127.0.0.1", "localhost")
	cert_path = tmp_path / "server.pem"
	key_path = tmp_path / "server.key"
	ca_path = tmp_path / "ca.pem"
	cert.cert_chain_pems[0].write_to_path(cert_path)
	cert.private_key_pem.write_to_path(key_path)
	ca.cert_pem.write_to_path(ca_path)
	return cert_path, key_path, ca_path


class RunningServer:
	def __init__(self, app: Any, port: int, cert_path: Path, key_path: Path, ca_path: Path):
		self.app = app
		self.port = port
		self.ca_path = ca_path
		self.config = uvicorn.Config(
			app,
			host="127.0.0.1",
			port=port,
			ssl_certfile=str(cert_path),
			ssl_keyfile=str(key_path),
			ws="wsproto",
			log_level="warning",
			access_log=False,
		)
		self.server = uvicorn.Server(self.config)
		self.thread = threading.Thread(target=self.server.run, daemon=True)

	def __enter__(self) -> "RunningServer":
		self.thread.start()
		deadline = time.time() + 10
		while time.time() < deadline:
			try:
				response = httpx.get(f"https://127.0.0.1:{self.port}/v1/health", verify=httpx_verify_config(str(self.ca_path)), timeout=0.5)
				if response.status_code == 200:
					return self
			except Exception:
				time.sleep(0.05)
		raise RuntimeError("server did not start")

	def __exit__(self, *_: Any) -> None:
		self.server.should_exit = True
		self.thread.join(timeout=10)


def assert_plaintext_absent(server_root: Path, plaintext: str) -> None:
	needle = plaintext.encode("utf-8")
	for path in server_root.rglob("*"):
		if path.is_file():
			assert needle not in path.read_bytes(), path


def assert_zip_has_no_private_key(path: Path) -> None:
	with zipfile.ZipFile(path) as archive:
		for name in archive.namelist():
			assert "server.key" not in name
			assert "secret_key" not in name
			assert "private" not in name.lower()
			data = archive.read(name)
			assert b"PRIVATE KEY BLOCK" not in data


def write_tampered_enrollment(source: Path, target: Path) -> None:
	with zipfile.ZipFile(source) as src, zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as dst:
		for name in src.namelist():
			data = src.read(name)
			if name == "identity.json":
				identity = parse_json_strict(data)
				identity["metadata"] = {"username": "bob", "display_name": "Mallory"}
				data = canonical_json_bytes(identity)
			dst.writestr(name, data)
