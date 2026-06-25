from __future__ import annotations

import asyncio
import hashlib
import json
import socket
import ssl
import threading
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
import trustme
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from websockets.asyncio.client import connect

from endpoint.client_core import EndpointClient
from endpoint.config import load_server_config
from endpoint.credentials import generate_client_token, hash_client_token, validate_client_token_strength, verify_client_token
from endpoint.crypto import OpenPgpContext, canonical_public_key_bytes, endpoint_fingerprint, verify_detached
from endpoint.errors import EndpointError
from endpoint.protocol import PROTOCOL_VERSION, canonical_json_bytes, parse_json_strict, validate_encrypted_envelope, validate_metadata
from endpoint.server_core import ServerConfig, create_app
from endpoint.transport import FederationPolicy, httpx_verify_config, normalize_server_url, validate_https_url


def free_port() -> int:
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
		sock.bind(("127.0.0.1", 0))
		return sock.getsockname()[1]


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


def make_client(tmp_path: Path, name: str, server_url: str, token: str) -> EndpointClient:
	client = EndpointClient(
		client_ref=name,
		home_server_url=server_url,
		auth_token=token,
		key_store_dir=tmp_path / "clients" / name / "openpgp",
		state_dir=tmp_path / "clients" / name / "state",
		verify_tls=str(tmp_path / "ca.pem"),
	)
	client.ensure_identity(name=f"Endpoint {name}", email=f"{name}@endpoint.test")
	return client


def policy_for(*ports: int, outbound: set[str] | None = None) -> FederationPolicy:
	return FederationPolicy(
		public_federation=True,
		outbound_whitelist=outbound or set(),
		inbound_whitelist=set(),
		allow_private_networks=True,
		allowed_ports=set(ports),
		mode="public",
	)


def make_server_config(
	tmp_path: Path,
	name: str,
	url: str,
	identity: dict[str, Any],
	token: str,
	ports: tuple[int, ...],
	outbound: set[str] | None = None,
	verify_identity: bool = True,
	lease_seconds: int = 1,
	rejected_policy: str = "drop",
) -> ServerConfig:
	return ServerConfig(
		server_url=url,
		state_dir=tmp_path / "servers" / name,
		hosted_identities={identity["client_ref"]: identity},
		client_token_hashes={identity["client_ref"]: hash_client_token(token, allow_weak=True)},
		ca_bundle=str(tmp_path / "ca.pem"),
		federation_policy=policy_for(*ports, outbound=outbound),
		lease_seconds=lease_seconds,
		rejected_policy=rejected_policy,
		verify_hosted_identity_signatures=verify_identity,
	)


def make_server_config_document(
	tmp_path: Path,
	name: str,
	url: str,
	identity: dict[str, Any],
	token_hash: str,
	ports: tuple[int, ...],
	outbound: set[str] | None = None,
) -> dict[str, Any]:
	return {
		"protocol_version": PROTOCOL_VERSION,
		"server_url": url,
		"state_dir": str(tmp_path / "servers" / name),
		"hosted_identities": {identity["client_ref"]: identity},
		"client_token_hashes": {identity["client_ref"]: token_hash},
		"ca_bundle": str(tmp_path / "ca.pem"),
		"federation_policy": {
			"public_federation": True,
			"inbound_whitelist": [],
			"outbound_whitelist": sorted(outbound or []),
			"allow_private_networks": True,
			"allowed_ports": list(ports),
			"mode": "public",
		},
		"lease_seconds": 1,
		"rejected_policy": "drop",
		"debug_errors": False,
		"verify_hosted_identity_signatures": True,
	}


def write_config(path: Path, document: dict[str, Any]) -> Path:
	path.write_bytes(canonical_json_bytes(document))
	return path


def assert_no_server_private_key_material(server_root: Path) -> None:
	for path in server_root.rglob("*"):
		if path.is_file():
			data = path.read_bytes()
			assert b"PRIVATE KEY BLOCK" not in data
			assert b"private-keys-v1.d" not in str(path).encode("utf-8")


def assert_plaintext_absent(server_root: Path, plaintext: str) -> None:
	needle = plaintext.encode("utf-8")
	for path in server_root.rglob("*"):
		if path.is_file():
			assert needle not in path.read_bytes(), path


def short_fingerprint(fingerprint: str) -> str:
	return f"{fingerprint[:10]}...{fingerprint[-8:]}"


def trace_identity(trace: Any, label: str, identity: dict[str, Any]) -> None:
	trace(
		f"{label}: client_ref={identity['client_ref']} "
		f"fingerprint={short_fingerprint(identity['endpoint_fingerprint'])} "
		f"metadata={identity.get('metadata')}"
	)


def client_state_json(client: EndpointClient, name: str, default: Any) -> Any:
	path = client.state.state_dir / name
	if not path.exists():
		return default
	return json.loads(path.read_text(encoding="utf-8"))


def make_fake_peer_app(mode: str, identity: dict[str, Any] | None = None) -> FastAPI:
	app = FastAPI()

	@app.get("/v1/health")
	async def health() -> dict[str, str]:
		return {"status": "ok"}

	@app.get("/v1/federation/identity/{client_ref}")
	async def fake_identity(client_ref: str) -> Any:
		if mode == "identity_redirect":
			return RedirectResponse("https://example.com/redirected", status_code=307)
		if mode == "identity_invalid_json":
			return PlainTextResponse("not-json", media_type="application/json")
		if mode == "identity_list":
			return JSONResponse([])
		if mode == "identity_oversized":
			return PlainTextResponse("x" * (64 * 1024 + 1), media_type="application/json")
		return identity

	@app.post("/v1/federation/messages")
	async def fake_messages() -> Any:
		if mode == "messages_redirect":
			return RedirectResponse("https://example.com/redirected", status_code=307)
		return {"status": "queued"}

	return app


def tampered_envelope_from_inner(sender: EndpointClient, recipient_identity: dict[str, Any], envelope: dict[str, Any], inner: dict[str, Any]) -> dict[str, Any]:
	tampered = dict(envelope)
	tampered["ciphertext_armored"] = sender.openpgp.encrypt_to(recipient_identity["public_key_armored"], canonical_json_bytes(inner))
	tampered["ciphertext_sha256"] = hashlib.sha256(tampered["ciphertext_armored"].encode("utf-8")).hexdigest()
	return tampered


def resign_inner(sender: EndpointClient, inner: dict[str, Any]) -> None:
	inner["signature"] = sender.openpgp.sign_detached(sender.ensure_identity(), canonical_json_bytes(inner["payload"]))


def test_sequoia_openpgp_backend_isolated_key_stores_and_error_mapping(tmp_path: Path, trace: Any) -> None:
	alice = OpenPgpContext(tmp_path / "clients" / "alice" / "openpgp")
	bob = OpenPgpContext(tmp_path / "clients" / "bob" / "openpgp")
	alice_fingerprint = alice.generate_identity("Endpoint Alice", "alice@endpoint.test")
	bob_fingerprint = bob.generate_identity("Endpoint Bob", "bob@endpoint.test")
	alice_public = alice.export_public_key(alice_fingerprint)
	bob_public = bob.export_public_key(bob_fingerprint)
	assert alice.backend == "sequoia"
	assert bob.backend == "sequoia"
	assert alice.key_store_dir != bob.key_store_dir
	assert "BEGIN PGP PUBLIC KEY BLOCK" in alice_public
	assert "BEGIN PGP PUBLIC KEY BLOCK" in bob_public
	trace(f"Sequoia OpenPGP generated isolated Alice/Bob key stores: alice={alice.key_store_dir}, bob={bob.key_store_dir}")
	alice_canonical = canonical_public_key_bytes(alice_public)
	assert alice_canonical == canonical_public_key_bytes(alice_public)
	assert endpoint_fingerprint(alice_public) == endpoint_fingerprint(alice_public)
	trace("canonical public-key bytes and Endpoint fingerprints are stable for the same key")
	payload = b'{"message":"sequoia openpgp backend"}'
	signature = alice.sign_detached(alice_fingerprint, payload)
	assert "BEGIN PGP SIGNATURE" in signature
	verify_detached(alice_public, payload, signature)
	with pytest.raises(EndpointError) as signature_exc:
		verify_detached(alice_public, payload + b"!", signature)
	assert signature_exc.value.code == "signature_invalid"
	trace("detached signatures verify successfully and tampered payloads map to signature_invalid")
	ciphertext = alice.encrypt_to(bob_public, payload)
	assert "BEGIN PGP MESSAGE" in ciphertext
	assert bob.decrypt(ciphertext) == payload
	with pytest.raises(EndpointError) as decrypt_exc:
		bob.decrypt("not an armored ciphertext")
	assert decrypt_exc.value.code == "malformed_ciphertext"
	crypto_source = Path("endpoint/crypto.py").read_text(encoding="utf-8")
	forbidden_runtime_markers = ["subprocess", "ctypes", "GP" + "GME", "Gpg" + "4win", "Gnu" + "PG"]
	for marker in forbidden_runtime_markers:
		assert marker not in crypto_source
	trace("Sequoia OpenPGP encrypted/decrypted armored payloads and mapped malformed ciphertext safely")


def test_server_json_config_loading_is_strict_and_hash_only(tmp_path: Path, trace: Any) -> None:
	_, _, _ = make_tls(tmp_path)
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	token = generate_client_token()
	token_hash = hash_client_token(token)
	client = make_client(tmp_path, "alice", url, token)
	identity = client.export_identity({"username": "alice"})
	document = make_server_config_document(tmp_path, "config-valid", url, identity, token_hash, (port,), {url})
	document["server_url"] = f"https://LOCALHOST:{port}/"
	document["federation_policy"]["outbound_whitelist"] = [f"https://LOCALHOST:{port}/"]
	config_path = write_config(tmp_path / "server.json", document)
	config = load_server_config(config_path)
	assert config.server_url == f"https://localhost:{port}"
	assert config.federation_policy.outbound_whitelist == {f"https://localhost:{port}"}
	assert config.client_token_hashes["alice"] == token_hash
	create_app(config)
	trace("valid JSON server config loaded and created an app using hashed client credentials")
	for label, mutate in (
		("unknown top-level key", lambda item: item.update({"extra": True})),
		("missing required field", lambda item: item.pop("lease_seconds")),
		("bad protocol version", lambda item: item.update({"protocol_version": "bad"})),
		("bad server URL", lambda item: item.update({"server_url": "http://127.0.0.1"})),
		("bad lease seconds", lambda item: item.update({"lease_seconds": 0})),
		("bad rejected policy", lambda item: item.update({"rejected_policy": "archive"})),
		("bad federation port", lambda item: item["federation_policy"].update({"allowed_ports": [0]})),
		("raw token in hash map", lambda item: item.update({"client_token_hashes": {"alice": token}})),
		("malformed verifier", lambda item: item.update({"client_token_hashes": {"alice": "pbkdf2_sha256:1:not-base64:not-base64"}})),
	):
		bad = json.loads(json.dumps(document))
		mutate(bad)
		with pytest.raises(EndpointError) as exc:
			load_server_config(write_config(tmp_path / f"bad-{label.replace(' ', '-')}.json", bad))
		assert exc.value.code == "invalid_config"
	trace("strict config loading rejected malformed config shapes, raw tokens, and malformed verifiers")
	malformed_path = tmp_path / "malformed.json"
	malformed_path.write_text("{", encoding="utf-8")
	with pytest.raises(EndpointError) as malformed_exc:
		load_server_config(malformed_path)
	assert malformed_exc.value.code == "invalid_config"
	bad_identity = json.loads(json.dumps(document))
	bad_identity["hosted_identities"]["alice"]["endpoint_fingerprint"] = "ep1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	with pytest.raises(EndpointError):
		create_app(load_server_config(write_config(tmp_path / "bad-identity.json", bad_identity)))
	missing_hash = json.loads(json.dumps(document))
	missing_hash["client_token_hashes"] = {}
	with pytest.raises(EndpointError) as missing_hash_exc:
		create_app(load_server_config(write_config(tmp_path / "missing-token-hash.json", missing_hash)))
	assert missing_hash_exc.value.code == "invalid_config"
	trace("hosted identity fingerprint/signature validation still runs after config load")


@pytest.mark.asyncio
async def test_hashed_credentials_authenticate_and_do_not_leak_secrets(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	token = generate_client_token()
	wrong_token = generate_client_token()
	validate_client_token_strength(token)
	with pytest.raises(EndpointError):
		validate_client_token_strength("alice-token")
	with pytest.raises(EndpointError):
		hash_client_token("alice-token")
	token_hash = hash_client_token(token)
	assert verify_client_token(token, token_hash)
	assert not verify_client_token(wrong_token, token_hash)
	client = make_client(tmp_path, "alice", url, token)
	identity = client.export_identity({"username": "alice"})
	config = ServerConfig(
		server_url=url,
		state_dir=tmp_path / "servers" / "hashed-auth",
		hosted_identities={"alice": identity},
		client_token_hashes={"alice": token_hash},
		ca_bundle=str(ca_path),
		federation_policy=policy_for(port, outbound={url}),
		lease_seconds=1,
	)
	app = create_app(config)
	trace("testing HTTPS/WSS auth with hashed server-side credentials")
	with RunningServer(app, port, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			good = await http.post(
				f"{url}/v1/client/discover",
				json={"client_ref": "alice", "peer_server_url": url, "peer_client_ref": "alice"},
				headers={"Authorization": f"Bearer {token}"},
			)
			assert good.status_code == 200
			failures = []
			for headers, client_ref in (
				({}, "alice"),
				({"Authorization": "Basic abc"}, "alice"),
				({"Authorization": "Bearer"}, "alice"),
				({"Authorization": f"Bearer {wrong_token}"}, "alice"),
				({"Authorization": f"Bearer {token}"}, "mallory"),
			):
				response = await http.post(
					f"{url}/v1/client/discover",
					json={"client_ref": client_ref, "peer_server_url": url, "peer_client_ref": "alice"},
					headers=headers,
				)
				assert response.status_code == 401
				failures.append(response.json())
			assert all(item == failures[0] for item in failures)
			for body in failures:
				text = json.dumps(body)
				assert token not in text
				assert wrong_token not in text
				assert token_hash not in text
		with pytest.raises(EndpointError):
			app.state.endpoint.authenticate_client("alice", "Bearer ")
		ssl_context = ssl.create_default_context(cafile=str(ca_path))
		async with connect(f"wss://127.0.0.1:{port}/v1/client/alice/inbox", ssl=ssl_context, additional_headers={"Authorization": f"Bearer {token}"}):
			pass
		with pytest.raises(Exception):
			async with connect(f"wss://127.0.0.1:{port}/v1/client/alice/inbox", ssl=ssl_context, additional_headers={"Authorization": f"Bearer {wrong_token}"}):
				pass
	server_root = tmp_path / "servers" / "hashed-auth"
	for path in server_root.rglob("*"):
		if path.is_file():
			data = path.read_text(encoding="utf-8", errors="ignore")
			assert token not in data
			assert wrong_token not in data
			assert token_hash not in data
	trace("raw tokens and token hashes were absent from server state files, logs, and auth error bodies")


@pytest.mark.asyncio
async def test_identity_discovery_auth_trust_and_metadata_tamper(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_a, port_b = free_port(), free_port()
	url_a, url_b = f"https://127.0.0.1:{port_a}", f"https://127.0.0.1:{port_b}"
	trace(f"created local test CA and HTTPS endpoints: server_a={url_a}, server_b={url_b}")
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	trace(f"created isolated OpenPGP key stores: alice={client_a.openpgp.key_store_dir}, bob={client_b.openpgp.key_store_dir}")
	identity_a = client_a.export_identity({"username": "alice", "display_name": "Alice"})
	identity_b = client_b.export_identity({"username": "bob", "display_name": "Bob", "status": "online"})
	trace_identity(trace, "exported Alice public identity", identity_a)
	trace_identity(trace, "exported Bob public identity", identity_b)
	app_a = create_app(make_server_config(tmp_path, "a", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}))
	app_b = create_app(make_server_config(tmp_path, "b", url_b, identity_b, "bob-token", (port_a, port_b), {url_a}))
	with RunningServer(app_a, port_a, cert_path, key_path, ca_path), RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		trace("started Server A and Server B over HTTPS/WSS with configured public identities")
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			missing = await http.post(f"{url_a}/v1/client/identity", json={}, headers={"Authorization": "Bearer alice-token"})
			assert missing.status_code == 404
			trace("confirmed no public client identity-management endpoint exists")
			bad = await http.post(f"{url_a}/v1/client/discover", json={"client_ref": "alice"}, headers={"Authorization": "Bearer wrong"})
			assert bad.status_code == 401
			trace("confirmed bad HTTPS client auth is rejected for discovery")
		with pytest.raises(Exception):
			ssl_context = ssl.create_default_context(cafile=str(ca_path))
			async with connect(f"wss://127.0.0.1:{port_a}/v1/client/alice/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer wrong"}):
				pass
		trace("confirmed bad WSS client auth is rejected before inbox delivery")
		result = await client_a.discover(url_b, "bob")
		assert result.identity["endpoint_fingerprint"] == identity_b["endpoint_fingerprint"]
		assert result.trust_state == "untrusted"
		assert result.route_warning is None
		assert result.pin_state is None
		trace(
			"Client A discovered Bob through Server A -> Server B; "
			f"fingerprint={short_fingerprint(result.identity['endpoint_fingerprint'])}, trust=untrusted"
		)
		pinned = await client_a.discover(url_b, "bob", identity_b["endpoint_fingerprint"])
		assert pinned.pin_state == "matched"
		assert pinned.trust_state == "untrusted"
		assert client_a.state.contact_pin(url_b, "bob") == identity_b["endpoint_fingerprint"]
		trace("Client A repeated discovery with Bob's out-of-band fingerprint pin and saw a matching identity")
		client_a.mark_trusted(result.identity["endpoint_fingerprint"])
		assert client_a.trust_state(result.identity["endpoint_fingerprint"]) == "trusted"
		trace("Client A explicitly marked Bob's fingerprint trusted")
	tampered_b = dict(identity_b)
	tampered_b["metadata"] = {"username": "bob", "display_name": "Mallory"}
	trace("mutated Bob metadata on the server side without creating a new identity signature")
	app_a2 = create_app(make_server_config(tmp_path, "a2", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}))
	app_b2 = create_app(make_server_config(tmp_path, "b2", url_b, tampered_b, "bob-token", (port_a, port_b), {url_a}, verify_identity=False))
	with RunningServer(app_a2, port_a, cert_path, key_path, ca_path), RunningServer(app_b2, port_b, cert_path, key_path, ca_path):
		with pytest.raises(EndpointError) as exc:
			await client_a.discover(url_b, "bob")
		assert exc.value.code == "invalid_identity_signature"
		trace("Client A rejected the tampered identity because the metadata signature no longer verified")


@pytest.mark.asyncio
async def test_pinned_first_contact_mismatch_is_atomic_and_recoverable(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_a, port_b = free_port(), free_port()
	url_a, url_b = f"https://127.0.0.1:{port_a}", f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b_real = make_client(tmp_path, "bob-real", url_b, "bob-token")
	client_b_attacker = make_client(tmp_path, "bob-attacker", url_b, "bob-token")
	client_b_real.client_ref = "bob"
	client_b_attacker.client_ref = "bob"
	identity_a = client_a.export_identity({"username": "alice"})
	identity_b_real = client_b_real.export_identity({"username": "bob", "display_name": "Bob"})
	identity_b_attacker = client_b_attacker.export_identity({"username": "bob", "display_name": "Bob"})
	assert identity_b_attacker["endpoint_fingerprint"] != identity_b_real["endpoint_fingerprint"]
	trace_identity(trace, "real out-of-band Bob contact identity", identity_b_real)
	trace_identity(trace, "malicious first-contact substitute identity", identity_b_attacker)
	app_a1 = create_app(make_server_config(tmp_path, "atomic-a1", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}))
	app_b_bad = create_app(make_server_config(tmp_path, "atomic-bad", url_b, identity_b_attacker, "bob-token", (port_a, port_b), {url_a}))
	with RunningServer(app_a1, port_a, cert_path, key_path, ca_path), RunningServer(app_b_bad, port_b, cert_path, key_path, ca_path):
		with pytest.raises(EndpointError) as exc:
			await client_a.discover(url_b, "bob", identity_b_real["endpoint_fingerprint"])
		assert exc.value.code == "contact_fingerprint_mismatch"
		assert client_state_json(client_a, "identities.json", {}) == {}
		assert client_state_json(client_a, "routes.json", {}) == {}
		assert client_state_json(client_a, "contact_pins.json", {}) == {}
		trace("pinned first-contact discovery rejected the substitute before writing identity, route, or pin state")
	app_a2 = create_app(make_server_config(tmp_path, "atomic-a2", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}))
	app_b_real = create_app(make_server_config(tmp_path, "atomic-real", url_b, identity_b_real, "bob-token", (port_a, port_b), {url_a}))
	with RunningServer(app_a2, port_a, cert_path, key_path, ca_path), RunningServer(app_b_real, port_b, cert_path, key_path, ca_path):
		recovered = await client_a.discover(url_b, "bob", identity_b_real["endpoint_fingerprint"])
		assert recovered.pin_state == "matched"
		assert recovered.route_warning is None
		assert recovered.trust_state == "untrusted"
		reloaded = EndpointClient(
			client_ref="alice",
			home_server_url=url_a,
			auth_token="alice-token",
			key_store_dir=tmp_path / "clients" / "alice" / "openpgp",
			state_dir=tmp_path / "clients" / "alice" / "state",
			verify_tls=str(ca_path),
		)
		assert reloaded.state.contact_pin(url_b, "bob") == identity_b_real["endpoint_fingerprint"]
		persisted = await reloaded.discover(f"{url_b}/", "bob", reloaded.state.contact_pin(url_b, "bob"))
		assert persisted.pin_state == "matched"
		assert reloaded.state.contact_pin(url_b, "bob") == identity_b_real["endpoint_fingerprint"]
		assert client_state_json(reloaded, "identities.json", {}) == {identity_b_real["endpoint_fingerprint"]: identity_b_real}
		assert client_state_json(reloaded, "routes.json", {}) == {f"{url_b}|bob": [identity_b_real["endpoint_fingerprint"]]}
		trace("the same imported pin survived client reload and the correct Bob identity was discoverable afterward")


@pytest.mark.asyncio
async def test_full_exchange_offline_online_wss_ack_and_plaintext_absence(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_a, port_b = free_port(), free_port()
	url_a, url_b = f"https://127.0.0.1:{port_a}", f"https://127.0.0.1:{port_b}"
	trace(f"created HTTPS/WSS test servers: server_a={url_a}, server_b={url_b}")
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_a = client_a.export_identity({"username": "alice", "display_name": "Alice"})
	identity_b = client_b.export_identity({"username": "bob", "display_name": "Bob"})
	trace_identity(trace, "Alice identity configured into Server A", identity_a)
	trace_identity(trace, "Bob identity configured into Server B", identity_b)
	app_a = create_app(make_server_config(tmp_path, "a", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}))
	app_b = create_app(make_server_config(tmp_path, "b", url_b, identity_b, "bob-token", (port_a, port_b), {url_a}))
	body_ab = "distinctive plaintext A to B 9c347ebf"
	body_ba = "distinctive plaintext B to A 41a6ec50"
	with RunningServer(app_a, port_a, cert_path, key_path, ca_path), RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		trace("started both servers; Bob is offline because no WSS inbox is connected yet")
		discovered_b = await client_a.discover(url_b, "bob")
		trace(f"Alice discovered Bob's key, trust={discovered_b.trust_state}; sending while still untrusted is allowed")
		send_result = await client_a.send_message(discovered_b.identity, url_b, body_ab, {"username": "alice"})
		assert send_result.recipient_trust_state == "untrusted"
		trace(f"Alice submitted signed+encrypted message {send_result.message_id} to Server A")
		assert app_b.state.endpoint.queue.count_active("bob") == 1
		assert_plaintext_absent(tmp_path / "servers" / "b", body_ab)
		trace("Server A proxied ciphertext to Server B; Server B queued one encrypted envelope for offline Bob")
		messages_b = await client_b.receive_messages(limit=1, timeout=5)
		assert [message.body for message in messages_b] == [body_ab]
		assert messages_b[0].sender_metadata == {"username": "alice"}
		assert messages_b[0].sender_trust_state == "untrusted"
		assert client_b.state.contact_pin(url_a, "alice") is None
		trace(
			"Bob connected over WSS, received the queued envelope, decrypted it, "
			"verified Alice's signature, and saw Alice as untrusted without auto-pinning her"
		)
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		trace("Bob acked over WSS; Server B removed the queued message from active queue state")
		reply_identity = {
			"protocol_version": PROTOCOL_VERSION,
			"client_ref": messages_b[0].raw_payload["sender_route"]["client_ref"],
			"public_key_armored": messages_b[0].raw_payload["sender_public_key_armored"],
			"endpoint_fingerprint": messages_b[0].sender_fingerprint,
			"metadata": messages_b[0].sender_metadata,
		}
		await client_b.send_message(reply_identity, url_a, body_ba, None)
		trace("Bob replied using Alice's public key embedded inside the decrypted message; Bob omitted metadata")
		messages_a = await client_a.receive_messages(limit=1, timeout=5)
		assert [message.body for message in messages_a] == [body_ba]
		assert messages_a[0].sender_metadata is None
		assert client_a.state.contact_pin(url_b, "bob") is None
		trace("Alice received Bob's reply over WSS and verified/decrypted it successfully")
	for root in (tmp_path / "servers").iterdir():
		assert_no_server_private_key_material(root)
		assert_plaintext_absent(root, body_ab)
		assert_plaintext_absent(root, body_ba)
		trace(f"checked server state/log files under {root.name}: no private keys and no distinctive plaintext bodies")


@pytest.mark.asyncio
async def test_route_key_change_is_new_untrusted_identity(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_a, port_b = free_port(), free_port()
	url_a, url_b = f"https://127.0.0.1:{port_a}", f"https://127.0.0.1:{port_b}"
	trace(f"testing route continuity at route server={url_b}, client_ref=bob")
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b1 = make_client(tmp_path, "bob1", url_b, "bob-token")
	client_b2 = make_client(tmp_path, "bob2", url_b, "bob-token")
	client_b2.client_ref = "bob"
	identity_a = client_a.export_identity({"username": "alice"})
	client_b1.client_ref = "bob"
	identity_b1 = client_b1.export_identity({"username": "bob"})
	identity_b2 = client_b2.export_identity({"username": "bob"})
	trace_identity(trace, "first Bob identity for route", identity_b1)
	trace_identity(trace, "second Bob identity with same metadata/route but different key", identity_b2)
	app_a1 = create_app(make_server_config(tmp_path, "a1", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}))
	app_b1 = create_app(make_server_config(tmp_path, "b1", url_b, identity_b1, "bob-token", (port_a, port_b), {url_a}))
	with RunningServer(app_a1, port_a, cert_path, key_path, ca_path), RunningServer(app_b1, port_b, cert_path, key_path, ca_path):
		first = await client_a.discover(url_b, "bob")
		assert first.route_warning is None
		trace(f"first discovery recorded fingerprint {short_fingerprint(first.identity['endpoint_fingerprint'])} with no warning")
	app_a2 = create_app(make_server_config(tmp_path, "a2", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}))
	app_b2 = create_app(make_server_config(tmp_path, "b2", url_b, identity_b2, "bob-token", (port_a, port_b), {url_a}))
	with RunningServer(app_a2, port_a, cert_path, key_path, ca_path), RunningServer(app_b2, port_b, cert_path, key_path, ca_path):
		identities_path = tmp_path / "clients" / "alice" / "state" / "identities.json"
		identities_before = parse_json_strict(identities_path.read_text(encoding="utf-8"))
		routes_before = client_state_json(client_a, "routes.json", {})
		pins_before = client_state_json(client_a, "contact_pins.json", {})
		with pytest.raises(EndpointError) as pinned_exc:
			await client_a.discover(url_b, "bob", first.identity["endpoint_fingerprint"])
		assert pinned_exc.value.code == "contact_fingerprint_mismatch"
		identities_after = parse_json_strict(identities_path.read_text(encoding="utf-8"))
		assert identities_after == identities_before
		assert client_state_json(client_a, "routes.json", {}) == routes_before
		assert client_state_json(client_a, "contact_pins.json", {}) == pins_before
		trace("pinned discovery rejected the substituted Bob key before storing it")
		second = await client_a.discover(url_b, "bob")
		assert second.route_warning == "route_key_changed"
		assert second.identity["endpoint_fingerprint"] != first.identity["endpoint_fingerprint"]
		assert second.trust_state == "untrusted"
		trace(
			"second discovery returned a different fingerprint; client kept it as a new untrusted identity "
			f"and surfaced warning={second.route_warning}"
		)


@pytest.mark.asyncio
async def test_lease_expiry_redelivery_and_reject_drop_for_poison_message(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_a, port_b = free_port(), free_port()
	url_a, url_b = f"https://127.0.0.1:{port_a}", f"https://127.0.0.1:{port_b}"
	trace("testing WSS lease redelivery and poison-message reject/drop behavior")
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_a = client_a.export_identity({"username": "alice"})
	identity_b = client_b.export_identity({"username": "bob"})
	app_a = create_app(make_server_config(tmp_path, "a", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}, lease_seconds=1))
	app_b = create_app(make_server_config(tmp_path, "b", url_b, identity_b, "bob-token", (port_a, port_b), {url_a}, lease_seconds=1))
	with RunningServer(app_a, port_a, cert_path, key_path, ca_path), RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		discovered_b = await client_a.discover(url_b, "bob")
		await client_a.send_message(discovered_b.identity, url_b, "lease redelivery body")
		trace("queued a signed+encrypted message for Bob")
		ssl_context = ssl.create_default_context(cafile=str(ca_path))
		async with connect(f"wss://127.0.0.1:{port_b}/v1/client/bob/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer bob-token"}) as websocket:
			first_frame = parse_json_strict(await asyncio.wait_for(websocket.recv(), timeout=5))
			trace(f"Bob received message {first_frame['envelope']['message_id']} over WSS but disconnected without ack")
		await asyncio.sleep(1.3)
		trace("lease expired, making the same queued message eligible for redelivery")
		async with connect(f"wss://127.0.0.1:{port_b}/v1/client/bob/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer bob-token"}) as websocket:
			second_frame = parse_json_strict(await asyncio.wait_for(websocket.recv(), timeout=5))
			await websocket.send(json.dumps({"type": "ack", "message_id": second_frame["envelope"]["message_id"]}))
			ack_result = parse_json_strict(await asyncio.wait_for(websocket.recv(), timeout=5))
			assert ack_result == {"type": "ack_result", "message_id": second_frame["envelope"]["message_id"], "status": "ok"}
			trace(f"Bob received the same message again and acked {second_frame['envelope']['message_id']}")
		assert first_frame["envelope"]["message_id"] == second_frame["envelope"]["message_id"]
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		trace("ack removed the redelivered message from Server B's active queue")
		poison = client_a.build_message_envelope(discovered_b.identity, url_b, "poison body")
		poison["message_id"] = "outer-inner-mismatch-id"
		trace("created poison envelope by changing the outer message_id after encryption")
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			response = await http.post(f"{url_b}/v1/federation/messages", json=poison)
			assert response.status_code == 200
		trace("Server B accepted the opaque encrypted poison envelope into the queue")
		messages = await client_b.receive_messages(limit=1, timeout=2)
		assert messages == []
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		trace("Bob rejected the permanently invalid envelope over WSS; Server B dropped it instead of redelivering forever")


@pytest.mark.asyncio
async def test_signature_wrong_recipient_and_duplicate_rejections(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_a, port_b = free_port(), free_port()
	url_a, url_b = f"https://127.0.0.1:{port_a}", f"https://127.0.0.1:{port_b}"
	trace("testing client-side duplicate, signature, wrong-recipient, and server-side duplicate rejection")
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_a = client_a.export_identity({"username": "alice"})
	identity_b = client_b.export_identity({"username": "bob"})
	app_b = create_app(make_server_config(tmp_path, "b", url_b, identity_b, "bob-token", (port_a, port_b), {url_a}))
	good = client_a.build_message_envelope(identity_b, url_b, "signed body")
	with pytest.raises(EndpointError) as duplicate_exc:
		client_b.process_envelope(good)
		client_b.process_envelope(good)
	assert duplicate_exc.value.code == "duplicate_message_id"
	trace("client accepted a valid message once, then rejected the same message_id as a duplicate")
	tampered_inner = parse_json_strict(client_b.openpgp.decrypt(good["ciphertext_armored"]))
	tampered_inner["payload"]["body"] = "tampered body"
	bad_sig = dict(good)
	bad_sig["message_id"] = "bad-signature-message"
	tampered_inner["payload"]["message_id"] = bad_sig["message_id"]
	bad_sig["ciphertext_armored"] = client_a.openpgp.encrypt_to(identity_b["public_key_armored"], canonical_json_bytes(tampered_inner))
	bad_sig["ciphertext_sha256"] = hashlib.sha256(bad_sig["ciphertext_armored"].encode("utf-8")).hexdigest()
	with pytest.raises(EndpointError) as sig_exc:
		client_b.process_envelope(bad_sig)
	assert sig_exc.value.code == "signature_invalid"
	trace("client rejected a payload whose body changed without a matching detached signature")
	wrong_inner = parse_json_strict(client_b.openpgp.decrypt(good["ciphertext_armored"]))
	wrong_inner["payload"]["message_id"] = "wrong-recipient-message"
	wrong_inner["payload"]["recipient_fingerprint"] = "ep1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	wrong_inner["payload"]["recipient_route"] = good["recipient_route"]
	wrong_inner["signature"] = client_a.openpgp.sign_detached(client_a.ensure_identity(), canonical_json_bytes(wrong_inner["payload"]))
	wrong = dict(good)
	wrong["message_id"] = wrong_inner["payload"]["message_id"]
	wrong["recipient_fingerprint"] = wrong_inner["payload"]["recipient_fingerprint"]
	wrong["ciphertext_armored"] = client_a.openpgp.encrypt_to(identity_b["public_key_armored"], canonical_json_bytes(wrong_inner))
	wrong["ciphertext_sha256"] = hashlib.sha256(wrong["ciphertext_armored"].encode("utf-8")).hexdigest()
	with pytest.raises(EndpointError) as wrong_exc:
		client_b.process_envelope(wrong)
	assert wrong_exc.value.code == "wrong_recipient"
	trace("client rejected a signed message whose inner recipient fingerprint did not match Bob")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			first = await http.post(f"{url_b}/v1/federation/messages", json=bad_sig)
			second = await http.post(f"{url_b}/v1/federation/messages", json=bad_sig)
			assert first.status_code == 200
			assert second.status_code == 409
			trace("server accepted the first opaque envelope but rejected the second copy as duplicate message_id")


def test_metadata_limits_private_network_policy_and_mode_representation(tmp_path: Path, trace: Any) -> None:
	trace("testing metadata limits and federation network policy")
	with pytest.raises(EndpointError):
		validate_metadata({"username": "not valid space"})
	trace("rejected invalid username")
	with pytest.raises(EndpointError):
		validate_metadata({"display_name": "x" * 129})
	trace("rejected oversized display_name")
	with pytest.raises(EndpointError):
		validate_metadata({"custom": "x" * (17 * 1024)})
	trace("rejected oversized custom metadata")
	policy = FederationPolicy(
		public_federation=True,
		inbound_whitelist={"https://peer.example"},
		outbound_whitelist={"https://peer.example"},
		allow_private_networks=False,
		allowed_ports={443},
		mode="public",
	)
	assert policy.public_federation is True
	assert policy.inbound_whitelist == {"https://peer.example"}
	assert policy.outbound_whitelist == {"https://peer.example"}
	assert policy.allow_private_networks is False
	with pytest.raises(EndpointError):
		validate_https_url("https://127.0.0.1", policy, "outbound")
	trace("public-mode federation rejected loopback/private address by default")
	internal = FederationPolicy(allow_private_networks=True, allowed_ports={443}, mode="internal")
	assert validate_https_url("https://127.0.0.1", internal, "outbound") == "https://127.0.0.1"
	trace("internal deployment mode explicitly allowed the loopback address")


@pytest.mark.asyncio
async def test_bad_http_request_shapes_and_error_redaction(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	client = make_client(tmp_path, "alice", url, "alice-token")
	identity = client.export_identity({"username": "alice"})
	config = make_server_config(tmp_path, "bad-http", url, identity, "alice-token", (port,), {url})
	app = create_app(config)
	trace("testing malformed JSON, non-object JSON, missing fields, and safe default error output")
	with RunningServer(app, port, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			malformed = await http.post(
				f"{url}/v1/client/discover",
				content="{",
				headers={"Authorization": "Bearer alice-token", "content-type": "application/json"},
			)
			assert malformed.status_code == 400
			assert malformed.json()["error"]["code"] == "invalid_envelope"
			assert "detail" not in malformed.json()["error"]
			trace("malformed JSON returned a stable invalid_envelope error without debug details")
			list_body = await http.post(
				f"{url}/v1/client/messages",
				json=[],
				headers={"Authorization": "Bearer alice-token"},
			)
			assert list_body.status_code == 400
			assert list_body.json()["error"]["code"] == "invalid_envelope"
			trace("non-object JSON body was rejected")
			missing_fields = await http.post(
				f"{url}/v1/federation/messages",
				json={},
			)
			assert missing_fields.status_code == 400
			assert missing_fields.json()["error"]["code"] == "invalid_envelope"
			trace("missing required envelope fields were rejected")
	debug_config = make_server_config(tmp_path, "bad-http-debug", url, identity, "alice-token", (port,), {url})
	debug_config.debug_errors = True
	debug_app = create_app(debug_config)
	with RunningServer(debug_app, port, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			debug_response = await http.post(
				f"{url}/v1/client/discover",
				content="{",
				headers={"Authorization": "Bearer alice-token", "content-type": "application/json"},
			)
			assert debug_response.status_code == 400
			assert "detail" in debug_response.json()["error"]
			trace("debug mode includes safe parser detail while default mode does not")


@pytest.mark.asyncio
async def test_bad_envelope_whitelist_and_malformed_ciphertext_handling(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_a, port_b, port_c = free_port(), free_port(), free_port()
	url_a, url_b, url_c = f"https://127.0.0.1:{port_a}", f"https://127.0.0.1:{port_b}", f"https://127.0.0.1:{port_c}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_a = client_a.export_identity({"username": "alice"})
	identity_b = client_b.export_identity({"username": "bob"})
	app_a = create_app(make_server_config(tmp_path, "bad-env-a", url_a, identity_a, "alice-token", (port_a, port_b, port_c), {url_b}))
	app_b = create_app(make_server_config(tmp_path, "bad-env-b", url_b, identity_b, "bob-token", (port_a, port_b, port_c), {url_a}))
	trace("testing outbound Whitelist rejection, envelope size/hash checks, and malformed ciphertext reject/drop")
	with RunningServer(app_a, port_a, cert_path, key_path, ca_path), RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		good = client_a.build_message_envelope(identity_b, url_b, "valid body")
		assert client_a.build_message_envelope(identity_b, f"{url_b}/", "normalized route")["recipient_route"]["server_url"] == url_b
		with pytest.raises(EndpointError) as bad_route_exc:
			client_a.build_message_envelope(identity_b, f"{url_b}/mailbox", "bad recipient route")
		assert bad_route_exc.value.code == "url_policy_denied"
		unknown_destination = client_a.build_message_envelope(identity_b, url_c, "wrong destination")
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			unknown = await http.post(
				f"{url_a}/v1/client/messages",
				json={"client_ref": "alice", "envelope": unknown_destination},
				headers={"Authorization": "Bearer alice-token"},
			)
			assert unknown.status_code == 400
			assert unknown.json()["error"]["code"] == "unknown_destination_server"
			trace("Server A rejected an outbound destination outside its outbound Whitelist")
			bad_route = dict(good)
			bad_route["recipient_route"] = dict(good["recipient_route"])
			bad_route["recipient_route"]["server_url"] = f"{url_b}/mailbox"
			bad_route_response = await http.post(f"{url_b}/v1/federation/messages", json=bad_route)
			assert bad_route_response.status_code == 400
			assert bad_route_response.json()["error"]["code"] == "invalid_envelope"
			assert app_b.state.endpoint.queue.count_active("bob") == 0
			trace("Server B rejected a non-origin recipient route before queueing")
			bad_hash = dict(good)
			bad_hash["message_id"] = "bad-hash-message"
			bad_hash["ciphertext_sha256"] = "0" * 64
			hash_response = await http.post(f"{url_b}/v1/federation/messages", json=bad_hash)
			assert hash_response.status_code == 400
			assert hash_response.json()["error"]["code"] == "invalid_envelope"
			trace("Server B rejected an envelope whose ciphertext_sha256 did not match the ciphertext")
			oversized = dict(good)
			oversized["message_id"] = "oversized-envelope"
			oversized["ciphertext_armored"] = "x" * (1024 * 1024 + 1)
			oversized["ciphertext_sha256"] = hashlib.sha256(oversized["ciphertext_armored"].encode("utf-8")).hexdigest()
			oversized_response = await http.post(f"{url_b}/v1/federation/messages", json=oversized)
			assert oversized_response.status_code == 400
			assert oversized_response.json()["error"]["code"] == "metadata_too_large"
			trace("Server B rejected an oversized encrypted message envelope")
			malformed_ciphertext = dict(good)
			malformed_ciphertext["message_id"] = "malformed-ciphertext"
			malformed_ciphertext["ciphertext_armored"] = "not an openpgp ciphertext"
			malformed_ciphertext["ciphertext_sha256"] = hashlib.sha256(malformed_ciphertext["ciphertext_armored"].encode("utf-8")).hexdigest()
			malformed_response = await http.post(f"{url_b}/v1/federation/messages", json=malformed_ciphertext)
			assert malformed_response.status_code == 200
			trace("Server B queued opaque malformed ciphertext because servers cannot decrypt client payloads")
		messages = await client_b.receive_messages(limit=1, timeout=2)
		assert messages == []
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		trace("Bob rejected malformed ciphertext over WSS, and Server B dropped it from the active queue")
	whitelist_config = make_server_config(tmp_path, "bad-env-b-whitelist", url_b, identity_b, "bob-token", (port_a, port_b), {url_a})
	whitelist_config.federation_policy.inbound_whitelist = {"https://trusted.example"}
	whitelist_app = create_app(whitelist_config)
	with RunningServer(whitelist_app, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			inbound = await http.post(f"{url_b}/v1/federation/messages", json=good)
			assert inbound.status_code == 400
			assert inbound.json()["error"]["code"] == "forbidden_peer"
			trace("inbound Whitelist mode rejected federation traffic from an untrusted sender route")


@pytest.mark.asyncio
async def test_wss_ack_and_reject_are_scoped_to_connected_client(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", f"https://127.0.0.1:{free_port()}", "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	client_c = make_client(tmp_path, "carol", url_b, "carol-token")
	identity_b = client_b.export_identity({"username": "bob"})
	identity_c = client_c.export_identity({"username": "carol"})
	config = make_server_config(tmp_path, "scoped-wss", url_b, identity_b, "bob-token", (port_b,), {url_b})
	config.hosted_identities["carol"] = identity_c
	config.client_token_hashes["carol"] = hash_client_token("carol-token", allow_weak=True)
	app_b = create_app(config)
	envelope = client_a.build_message_envelope(identity_b, url_b, "message for bob")
	trace("testing that Carol cannot ack or reject Bob's queued message")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			response = await http.post(f"{url_b}/v1/federation/messages", json=envelope)
			assert response.status_code == 200
		assert app_b.state.endpoint.queue.count_active("bob") == 1
		ssl_context = ssl.create_default_context(cafile=str(ca_path))
		async with connect(f"wss://127.0.0.1:{port_b}/v1/client/carol/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer carol-token"}) as websocket:
			await websocket.send(json.dumps({"type": "ack", "message_id": envelope["message_id"]}))
			await websocket.send(json.dumps({"type": "reject", "message_id": envelope["message_id"], "reason": "invalid_envelope"}))
			await asyncio.sleep(0.3)
		assert app_b.state.endpoint.queue.count_active("bob") == 1
		trace("Carol's ack/reject frames did not affect Bob's queue entry")
		messages = await client_b.receive_messages(limit=1, timeout=5)
		assert [message.body for message in messages] == ["message for bob"]
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		trace("Bob later received and acked his own queued message")


def test_protocol_validation_bad_data_matrix(tmp_path: Path, trace: Any) -> None:
	trace("testing protocol-level malformed JSON, metadata, envelope, and URL policy validation")
	with pytest.raises(EndpointError):
		parse_json_strict('{"a":1,"a":2}')
	trace("duplicate JSON keys were rejected")
	deep_metadata: dict[str, Any] = {"leaf": "ok"}
	for _ in range(9):
		deep_metadata = {"nested": deep_metadata}
	with pytest.raises(EndpointError):
		validate_metadata(deep_metadata)
	trace("deeply nested metadata was rejected")
	for metadata in ({"display_name": "bad\nname"}, {"status": "bad\tstatus"}, {"bad field": "value"}):
		with pytest.raises(EndpointError):
			validate_metadata(metadata)
	trace("metadata control characters and unsafe custom field names were rejected")
	for url in (
		"http://example.com",
		"ftp://example.com",
		"https://user:pass@example.com",
		"https://example.com/path",
		"https://example.com?query=1",
		"https://example.com/#fragment",
		"https://example.com:444",
	):
		with pytest.raises(EndpointError):
			validate_https_url(url, FederationPolicy(allowed_ports={443}, allow_private_networks=True), "outbound")
	assert normalize_server_url("HTTPS://EXAMPLE.com/") == "https://example.com"
	assert normalize_server_url("https://EXAMPLE.com:443/") == "https://example.com:443"
	assert normalize_server_url("https://EXAMPLE.com:8443/") == "https://example.com:8443"
	trace("invalid federation schemes, credentials, fragments, and disallowed ports were rejected")
	with pytest.raises(EndpointError):
		validate_encrypted_envelope([])
	with pytest.raises(EndpointError):
		validate_encrypted_envelope({"protocol_version": PROTOCOL_VERSION, "message_id": 123})
	trace("wrong envelope shapes and field types were rejected")


def test_invalid_hosted_identity_config_is_rejected_at_startup(tmp_path: Path, trace: Any) -> None:
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	client = make_client(tmp_path, "alice", url, "alice-token")
	identity = client.export_identity({"username": "alice"})
	trace("testing server startup validation for configured public identities")
	bad_fingerprint = dict(identity)
	bad_fingerprint["endpoint_fingerprint"] = "ep1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	with pytest.raises(EndpointError):
		create_app(make_server_config(tmp_path, "bad-start-fingerprint", url, bad_fingerprint, "alice-token", (port,), {url}))
	trace("server startup rejected configured identity with mismatched fingerprint")
	bad_signature = dict(identity)
	bad_signature["metadata"] = {"username": "mallory"}
	with pytest.raises(EndpointError):
		create_app(make_server_config(tmp_path, "bad-start-signature", url, bad_signature, "alice-token", (port,), {url}))
	trace("server startup rejected configured identity whose metadata no longer matched its signature")


@pytest.mark.asyncio
async def test_multi_client_hosting_routes_messages_to_correct_inbox(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	client_c = make_client(tmp_path, "carol", url_b, "carol-token")
	identity_b = client_b.export_identity({"username": "bob"})
	identity_c = client_c.export_identity({"username": "carol"})
	config = make_server_config(tmp_path, "multi-client", url_b, identity_b, "bob-token", (port_b,), {url_b})
	config.hosted_identities["carol"] = identity_c
	config.client_token_hashes["carol"] = hash_client_token("carol-token", allow_weak=True)
	app_b = create_app(config)
	trace("testing one server hosting Bob and Carol with isolated inbox queues")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			bob_envelope = client_a.build_message_envelope(identity_b, url_b, "message for bob")
			carol_envelope = client_a.build_message_envelope(identity_c, url_b, "message for carol")
			assert (await http.post(f"{url_b}/v1/federation/messages", json=bob_envelope)).status_code == 200
			assert (await http.post(f"{url_b}/v1/federation/messages", json=carol_envelope)).status_code == 200
		assert app_b.state.endpoint.queue.count_active("bob") == 1
		assert app_b.state.endpoint.queue.count_active("carol") == 1
		trace("Server B queued one message for Bob and one for Carol")
		carol_messages = await client_c.receive_messages(limit=1, timeout=5)
		assert [message.body for message in carol_messages] == ["message for carol"]
		assert app_b.state.endpoint.queue.count_active("bob") == 1
		assert app_b.state.endpoint.queue.count_active("carol") == 0
		trace("Carol received only Carol's message; Bob's queue was untouched")
		bob_messages = await client_b.receive_messages(limit=1, timeout=5)
		assert [message.body for message in bob_messages] == ["message for bob"]
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		trace("Bob later received Bob's message")


@pytest.mark.asyncio
async def test_queue_and_lease_state_survive_server_restart(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_b = client_b.export_identity({"username": "bob"})
	config = make_server_config(tmp_path, "restartable", url_b, identity_b, "bob-token", (port_b,), {url_b}, lease_seconds=1)
	first_app = create_app(config)
	envelope = client_a.build_message_envelope(identity_b, url_b, "restart persistence body")
	trace("testing queued and leased message state across server restart")
	with RunningServer(first_app, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			assert (await http.post(f"{url_b}/v1/federation/messages", json=envelope)).status_code == 200
		assert first_app.state.endpoint.queue.count_active("bob") == 1
		trace("queued encrypted message on first server instance")
	second_app = create_app(config)
	with RunningServer(second_app, port_b, cert_path, key_path, ca_path):
		assert second_app.state.endpoint.queue.count_active("bob") == 1
		ssl_context = ssl.create_default_context(cafile=str(ca_path))
		async with connect(f"wss://127.0.0.1:{port_b}/v1/client/bob/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer bob-token"}) as websocket:
			frame = parse_json_strict(await asyncio.wait_for(websocket.recv(), timeout=5))
			assert frame["envelope"]["message_id"] == envelope["message_id"]
		trace("second server instance delivered the queued message but Bob disconnected before ack")
		assert second_app.state.endpoint.queue.count_active("bob") == 1
	third_app = create_app(config)
	await asyncio.sleep(1.2)
	with RunningServer(third_app, port_b, cert_path, key_path, ca_path):
		messages = await client_b.receive_messages(limit=1, timeout=5)
		assert [message.body for message in messages] == ["restart persistence body"]
		assert third_app.state.endpoint.queue.count_active("bob") == 0
		trace("third server instance redelivered the expired leased message and removed it after ack")
	fourth_app = create_app(config)
	with RunningServer(fourth_app, port_b, cert_path, key_path, ca_path):
		assert fourth_app.state.endpoint.queue.count_active("bob") == 0
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			duplicate = await http.post(f"{url_b}/v1/federation/messages", json=envelope)
			assert duplicate.status_code == 409
			assert duplicate.json()["error"]["code"] == "duplicate_message_id"
		trace("acked message did not reappear after another restart")


@pytest.mark.asyncio
async def test_quarantine_mode_keeps_rejected_poison_messages_out_of_active_queue(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_b = client_b.export_identity({"username": "bob"})
	config = make_server_config(tmp_path, "quarantine", url_b, identity_b, "bob-token", (port_b,), {url_b}, rejected_policy="quarantine")
	app_b = create_app(config)
	poison = client_a.build_message_envelope(identity_b, url_b, "quarantine poison")
	poison["ciphertext_armored"] = "not an openpgp ciphertext"
	poison["ciphertext_sha256"] = hashlib.sha256(poison["ciphertext_armored"].encode("utf-8")).hexdigest()
	trace("testing quarantine policy for permanently invalid queued ciphertext")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			assert (await http.post(f"{url_b}/v1/federation/messages", json=poison)).status_code == 200
		assert app_b.state.endpoint.queue.count_active("bob") == 1
		messages = await client_b.receive_messages(limit=1, timeout=2)
		assert messages == []
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		rejected = app_b.state.endpoint.queue.read_rejected("bob", poison["message_id"])
		assert rejected is not None
		assert rejected["state"] == "rejected"
		assert rejected["reject_reason"] == "malformed_ciphertext"
		trace("Server B moved Bob's rejected poison message to quarantine with a safe reason code")


@pytest.mark.asyncio
async def test_multiple_queued_messages_partial_ack_and_redelivery(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_b = client_b.export_identity({"username": "bob"})
	config = make_server_config(tmp_path, "batch", url_b, identity_b, "bob-token", (port_b,), {url_b}, lease_seconds=1)
	app_b = create_app(config)
	trace("testing batch queue delivery with partial ack and redelivery of unacked messages")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			for index in range(3):
				envelope = client_a.build_message_envelope(identity_b, url_b, f"batch body {index}", message_id=f"batch-{index}")
				assert (await http.post(f"{url_b}/v1/federation/messages", json=envelope)).status_code == 200
		assert app_b.state.endpoint.queue.count_active("bob") == 3
		ssl_context = ssl.create_default_context(cafile=str(ca_path))
		async with connect(f"wss://127.0.0.1:{port_b}/v1/client/bob/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer bob-token"}) as websocket:
			frames = [parse_json_strict(await asyncio.wait_for(websocket.recv(), timeout=5)) for _ in range(3)]
			ids = [frame["envelope"]["message_id"] for frame in frames]
			assert ids == ["batch-0", "batch-1", "batch-2"]
			await websocket.send(json.dumps({"type": "ack", "message_id": "batch-0"}))
			await asyncio.sleep(0.3)
		assert app_b.state.endpoint.queue.count_active("bob") == 2
		trace("Bob acked only the first of three leased messages; two remained active")
		await asyncio.sleep(1.2)
		messages = await client_b.receive_messages(limit=2, timeout=5)
		assert sorted(message.message_id for message in messages) == ["batch-1", "batch-2"]
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		trace("after lease expiry, Bob received and acked only the two unacked batch messages")


@pytest.mark.asyncio
async def test_malformed_wss_frames_do_not_alter_queue_or_break_later_delivery(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_b = client_b.export_identity({"username": "bob"})
	app_b = create_app(make_server_config(tmp_path, "malformed-wss", url_b, identity_b, "bob-token", (port_b,), {url_b}))
	trace("testing malformed WSS frames before later valid delivery")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		ssl_context = ssl.create_default_context(cafile=str(ca_path))
		async with connect(f"wss://127.0.0.1:{port_b}/v1/client/bob/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer bob-token"}) as websocket:
			await websocket.send("not-json")
			await websocket.send(json.dumps(["not", "an", "object"]))
			await websocket.send(json.dumps({"type": "ack"}))
			await asyncio.sleep(0.5)
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		trace("malformed WSS frames were ignored and did not create or alter queue state")
		envelope = client_a.build_message_envelope(identity_b, url_b, "valid after malformed frames")
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			assert (await http.post(f"{url_b}/v1/federation/messages", json=envelope)).status_code == 200
		messages = await client_b.receive_messages(limit=1, timeout=5)
		assert [message.body for message in messages] == ["valid after malformed frames"]
		trace("server continued to deliver a later valid message after malformed WSS input")


@pytest.mark.asyncio
async def test_client_credentials_are_bound_to_client_ref(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	client_a = make_client(tmp_path, "alice", url, "alice-token")
	client_b = make_client(tmp_path, "bob", url, "bob-token")
	identity_a = client_a.export_identity({"username": "alice"})
	identity_b = client_b.export_identity({"username": "bob"})
	config = make_server_config(tmp_path, "credential-scope", url, identity_a, "alice-token", (port,), {url})
	config.hosted_identities["bob"] = identity_b
	config.client_token_hashes["bob"] = hash_client_token("bob-token", allow_weak=True)
	app = create_app(config)
	trace("testing that tokens authenticate one configured client_ref only")
	with RunningServer(app, port, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			alice_as_bob = await http.post(
				f"{url}/v1/client/messages",
				json={"client_ref": "bob"},
				headers={"Authorization": "Bearer alice-token"},
			)
			assert alice_as_bob.status_code == 401
			bob_as_alice = await http.post(
				f"{url}/v1/client/discover",
				json={"client_ref": "alice"},
				headers={"Authorization": "Bearer bob-token"},
			)
			assert bob_as_alice.status_code == 401
		with pytest.raises(Exception):
			ssl_context = ssl.create_default_context(cafile=str(ca_path))
			async with connect(f"wss://127.0.0.1:{port}/v1/client/mallory/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer alice-token"}):
				pass
		trace("cross-client HTTPS auth and unknown-client WSS auth were rejected")


@pytest.mark.asyncio
async def test_unknown_local_recipient_is_rejected_by_recipient_server(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_b = client_b.export_identity({"username": "bob"})
	app_b = create_app(make_server_config(tmp_path, "unknown-recipient", url_b, identity_b, "bob-token", (port_b,), {url_b}))
	envelope = client_a.build_message_envelope(identity_b, url_b, "unknown local recipient")
	envelope["recipient_route"] = {"server_url": url_b, "client_ref": "missing"}
	trace("testing recipient server rejection for unknown local client_ref")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			response = await http.post(f"{url_b}/v1/federation/messages", json=envelope)
			assert response.status_code == 404
			assert response.json()["error"]["code"] == "unknown_recipient"
		assert app_b.state.endpoint.queue.count_active("missing") == 0
		trace("Server B rejected the envelope before queueing because recipient client_ref was not hosted")


@pytest.mark.asyncio
async def test_signed_metadata_update_same_key_does_not_trigger_route_change(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_a, port_b = free_port(), free_port()
	url_a, url_b = f"https://127.0.0.1:{port_a}", f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_a = client_a.export_identity({"username": "alice"})
	identity_b_v1 = client_b.export_identity({"username": "bob", "status": "v1"})
	identity_b_v2 = client_b.export_identity({"username": "bob", "status": "v2"})
	trace("testing signed metadata update with the same key and route")
	app_a1 = create_app(make_server_config(tmp_path, "metadata-a1", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}))
	app_b1 = create_app(make_server_config(tmp_path, "metadata-b1", url_b, identity_b_v1, "bob-token", (port_a, port_b), {url_a}))
	with RunningServer(app_a1, port_a, cert_path, key_path, ca_path), RunningServer(app_b1, port_b, cert_path, key_path, ca_path):
		first = await client_a.discover(url_b, "bob")
		assert first.identity["metadata"]["status"] == "v1"
		assert first.route_warning is None
	app_a2 = create_app(make_server_config(tmp_path, "metadata-a2", url_a, identity_a, "alice-token", (port_a, port_b), {url_b}))
	app_b2 = create_app(make_server_config(tmp_path, "metadata-b2", url_b, identity_b_v2, "bob-token", (port_a, port_b), {url_a}))
	with RunningServer(app_a2, port_a, cert_path, key_path, ca_path), RunningServer(app_b2, port_b, cert_path, key_path, ca_path):
		second = await client_a.discover(url_b, "bob")
		assert second.identity["metadata"]["status"] == "v2"
		assert second.identity["endpoint_fingerprint"] == first.identity["endpoint_fingerprint"]
		assert second.route_warning is None
		trace("Client A accepted Bob's newly signed metadata with the same fingerprint and no route-change warning")


@pytest.mark.asyncio
async def test_federation_peer_redirects_and_bad_identity_responses_are_rejected(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_a = free_port()
	peer_ports = [free_port() for _ in range(5)]
	url_a = f"https://127.0.0.1:{port_a}"
	peer_urls = [f"https://127.0.0.1:{port}" for port in peer_ports]
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", peer_urls[-1], "bob-token")
	identity_a = client_a.export_identity({"username": "alice"})
	identity_b = client_b.export_identity({"username": "bob"})
	config_a = make_server_config(tmp_path, "peer-bad-a", url_a, identity_a, "alice-token", tuple([port_a, *peer_ports]), set(peer_urls))
	app_a = create_app(config_a)
	fake_apps = [
		make_fake_peer_app("identity_redirect"),
		make_fake_peer_app("identity_invalid_json"),
		make_fake_peer_app("identity_list"),
		make_fake_peer_app("identity_oversized"),
		make_fake_peer_app("messages_redirect", identity_b),
	]
	trace("testing bad federation peer behavior: redirects, invalid JSON, wrong JSON shape, oversized identity, and message redirect")
	with RunningServer(app_a, port_a, cert_path, key_path, ca_path), \
		RunningServer(fake_apps[0], peer_ports[0], cert_path, key_path, ca_path), \
		RunningServer(fake_apps[1], peer_ports[1], cert_path, key_path, ca_path), \
		RunningServer(fake_apps[2], peer_ports[2], cert_path, key_path, ca_path), \
		RunningServer(fake_apps[3], peer_ports[3], cert_path, key_path, ca_path), \
		RunningServer(fake_apps[4], peer_ports[4], cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			redirect = await http.post(
				f"{url_a}/v1/client/discover",
				json={"client_ref": "alice", "peer_server_url": peer_urls[0], "peer_client_ref": "bob"},
				headers={"Authorization": "Bearer alice-token"},
			)
			assert redirect.status_code == 502
			assert redirect.json()["error"]["code"] == "delivery_failed"
			trace("identity discovery refused a peer redirect instead of following it")
			invalid_json = await http.post(
				f"{url_a}/v1/client/discover",
				json={"client_ref": "alice", "peer_server_url": peer_urls[1], "peer_client_ref": "bob"},
				headers={"Authorization": "Bearer alice-token"},
			)
			assert invalid_json.status_code == 400
			assert invalid_json.json()["error"]["code"] == "invalid_envelope"
			trace("identity discovery rejected a peer response that was not JSON")
			wrong_shape = await http.post(
				f"{url_a}/v1/client/discover",
				json={"client_ref": "alice", "peer_server_url": peer_urls[2], "peer_client_ref": "bob"},
				headers={"Authorization": "Bearer alice-token"},
			)
			assert wrong_shape.status_code == 400
			assert wrong_shape.json()["error"]["code"] == "invalid_envelope"
			trace("identity discovery rejected a peer JSON array instead of an identity object")
			oversized = await http.post(
				f"{url_a}/v1/client/discover",
				json={"client_ref": "alice", "peer_server_url": peer_urls[3], "peer_client_ref": "bob"},
				headers={"Authorization": "Bearer alice-token"},
			)
			assert oversized.status_code == 400
			assert oversized.json()["error"]["code"] == "metadata_too_large"
			trace("identity discovery rejected an oversized peer identity response")
			envelope = client_a.build_message_envelope(identity_b, peer_urls[4], "redirected delivery")
			message_redirect = await http.post(
				f"{url_a}/v1/client/messages",
				json={"client_ref": "alice", "envelope": envelope},
				headers={"Authorization": "Bearer alice-token"},
			)
			assert message_redirect.status_code == 502
			assert message_redirect.json()["error"]["code"] == "delivery_failed"
			trace("message proxying refused a federation POST redirect instead of treating it as success")


def test_inner_payload_mismatch_and_signature_metadata_matrix(tmp_path: Path, trace: Any) -> None:
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{free_port()}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_b = client_b.export_identity({"username": "bob"})
	base = client_a.build_message_envelope(identity_b, url_b, "matrix body", message_id="matrix-base")
	trace("testing inner encrypted payload mismatches that servers cannot see but recipients must reject")
	for field, replacement in (
		("sender_route", {"server_url": url_a, "client_ref": "mallory"}),
		("recipient_route", {"server_url": url_b, "client_ref": "mallory"}),
		("created_at", "2000-01-01T00:00:00Z"),
		("protocol_version", "endpoint-poc-bad"),
	):
		inner = parse_json_strict(client_b.openpgp.decrypt(base["ciphertext_armored"]))
		inner["payload"][field] = replacement
		inner["payload"]["message_id"] = f"matrix-{field}"
		resign_inner(client_a, inner)
		envelope = dict(base)
		envelope["message_id"] = inner["payload"]["message_id"]
		tampered = tampered_envelope_from_inner(client_a, identity_b, envelope, inner)
		with pytest.raises(EndpointError) as exc:
			client_b.process_envelope(tampered)
		assert exc.value.code == "outer_inner_mismatch"
		trace(f"recipient rejected outer/inner mismatch for {field}")
	inner = parse_json_strict(client_b.openpgp.decrypt(base["ciphertext_armored"]))
	inner["sender_fingerprint"] = "ep1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	inner["payload"]["message_id"] = "matrix-inner-sender"
	resign_inner(client_a, inner)
	envelope = dict(base)
	envelope["message_id"] = inner["payload"]["message_id"]
	with pytest.raises(EndpointError) as sender_exc:
		client_b.process_envelope(tampered_envelope_from_inner(client_a, identity_b, envelope, inner))
	assert sender_exc.value.code == "signature_invalid"
	trace("recipient rejected a signed inner object whose sender_fingerprint did not match the payload")
	inner = parse_json_strict(client_b.openpgp.decrypt(base["ciphertext_armored"]))
	inner["signature_algorithm"] = "unsupported"
	inner["payload"]["message_id"] = "matrix-algorithm"
	resign_inner(client_a, inner)
	envelope = dict(base)
	envelope["message_id"] = inner["payload"]["message_id"]
	with pytest.raises(EndpointError) as algorithm_exc:
		client_b.process_envelope(tampered_envelope_from_inner(client_a, identity_b, envelope, inner))
	assert algorithm_exc.value.code == "signature_invalid"
	trace("recipient rejected an unsupported signature algorithm marker")


@pytest.mark.asyncio
async def test_same_message_id_is_scoped_per_recipient_and_concurrent_duplicates_are_rejected(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	client_c = make_client(tmp_path, "carol", url_b, "carol-token")
	identity_b = client_b.export_identity({"username": "bob"})
	identity_c = client_c.export_identity({"username": "carol"})
	config = make_server_config(tmp_path, "recipient-scope", url_b, identity_b, "bob-token", (port_b,), {url_b})
	config.hosted_identities["carol"] = identity_c
	config.client_token_hashes["carol"] = hash_client_token("carol-token", allow_weak=True)
	app_b = create_app(config)
	trace("testing replay scope per recipient and concurrent duplicate submission handling")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		bob_envelope = client_a.build_message_envelope(identity_b, url_b, "same id for bob", message_id="shared-id")
		carol_envelope = client_a.build_message_envelope(identity_c, url_b, "same id for carol", message_id="shared-id")
		duplicate = client_a.build_message_envelope(identity_b, url_b, "duplicate body", message_id="concurrent-duplicate")
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			bob_response = await http.post(f"{url_b}/v1/federation/messages", json=bob_envelope)
			carol_response = await http.post(f"{url_b}/v1/federation/messages", json=carol_envelope)
			assert bob_response.status_code == 200
			assert carol_response.status_code == 200
			trace("same message_id was accepted for two different recipient scopes")
			results = await asyncio.gather(
				http.post(f"{url_b}/v1/federation/messages", json=duplicate),
				http.post(f"{url_b}/v1/federation/messages", json=duplicate),
			)
			assert sorted(response.status_code for response in results) == [200, 409]
			trace("concurrent duplicate submissions for Bob produced one queue entry and one duplicate rejection")
		assert app_b.state.endpoint.queue.count_active("bob") == 2
		assert app_b.state.endpoint.queue.count_active("carol") == 1
		bob_messages = await client_b.receive_messages(limit=2, timeout=5)
		carol_messages = await client_c.receive_messages(limit=1, timeout=5)
		assert sorted(message.body for message in bob_messages) == ["duplicate body", "same id for bob"]
		assert [message.body for message in carol_messages] == ["same id for carol"]
		trace("Bob and Carol received their separately scoped messages")


@pytest.mark.asyncio
async def test_parallel_wss_connections_do_not_receive_same_lease_simultaneously(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_b = client_b.export_identity({"username": "bob"})
	app_b = create_app(make_server_config(tmp_path, "parallel-wss", url_b, identity_b, "bob-token", (port_b,), {url_b}, lease_seconds=1))
	envelope = client_a.build_message_envelope(identity_b, url_b, "single leased message")
	trace("testing two simultaneous Bob WSS connections against one queued message")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			assert (await http.post(f"{url_b}/v1/federation/messages", json=envelope)).status_code == 200
		ssl_context = ssl.create_default_context(cafile=str(ca_path))
		async with connect(f"wss://127.0.0.1:{port_b}/v1/client/bob/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer bob-token"}) as ws1, \
			connect(f"wss://127.0.0.1:{port_b}/v1/client/bob/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer bob-token"}) as ws2:
			tasks = {asyncio.create_task(ws1.recv()): ws1, asyncio.create_task(ws2.recv()): ws2}
			done, pending = await asyncio.wait(tasks.keys(), timeout=2, return_when=asyncio.FIRST_COMPLETED)
			assert len(done) == 1
			receiver = tasks[next(iter(done))]
			frame = parse_json_strict(next(iter(done)).result())
			assert frame["envelope"]["message_id"] == envelope["message_id"]
			await receiver.send(json.dumps({"type": "ack", "message_id": envelope["message_id"]}))
			for task in pending:
				task.cancel()
			await asyncio.sleep(0.3)
		assert app_b.state.endpoint.queue.count_active("bob") == 0
		trace("only one WSS connection received the leased message before ack removed it")


@pytest.mark.asyncio
async def test_reject_reason_is_sanitized_before_quarantine_and_logs_do_not_leak_tokens(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port_b = free_port()
	url_a = f"https://127.0.0.1:{free_port()}"
	url_b = f"https://127.0.0.1:{port_b}"
	client_a = make_client(tmp_path, "alice", url_a, "alice-token")
	client_b = make_client(tmp_path, "bob", url_b, "bob-token")
	identity_b = client_b.export_identity({"username": "bob"})
	config = make_server_config(tmp_path, "sanitize-reject", url_b, identity_b, "bob-token", (port_b,), {url_b}, rejected_policy="quarantine")
	app_b = create_app(config)
	envelope = client_a.build_message_envelope(identity_b, url_b, "reject sanitization")
	bad_token = "bad-token-should-not-be-logged"
	trace("testing reject reason sanitization and absence of raw auth tokens in structured logs")
	with RunningServer(app_b, port_b, cert_path, key_path, ca_path):
		async with httpx.AsyncClient(verify=httpx_verify_config(str(ca_path)), timeout=5.0, follow_redirects=False) as http:
			assert (await http.post(f"{url_b}/v1/federation/messages", json=envelope)).status_code == 200
			bad_auth = await http.post(
				f"{url_b}/v1/client/discover",
				json={"client_ref": "bob"},
				headers={"Authorization": f"Bearer {bad_token}"},
			)
			assert bad_auth.status_code == 401
		ssl_context = ssl.create_default_context(cafile=str(ca_path))
		async with connect(f"wss://127.0.0.1:{port_b}/v1/client/bob/inbox", ssl=ssl_context, additional_headers={"Authorization": "Bearer bob-token"}) as websocket:
			frame = parse_json_strict(await asyncio.wait_for(websocket.recv(), timeout=5))
			assert frame["envelope"]["message_id"] == envelope["message_id"]
			await websocket.send(json.dumps({"type": "reject", "message_id": envelope["message_id"], "reason": "secret details " + ("x" * 500)}))
			reject_result = parse_json_strict(await asyncio.wait_for(websocket.recv(), timeout=5))
			assert reject_result == {"type": "reject_result", "message_id": envelope["message_id"], "status": "ok"}
		rejected = app_b.state.endpoint.queue.read_rejected("bob", envelope["message_id"])
		assert rejected is not None
		assert rejected["reject_reason"] == "invalid_envelope"
		log_text = (tmp_path / "servers" / "sanitize-reject" / "logs" / "structured.jsonl").read_text(encoding="utf-8")
		assert bad_token not in log_text
		assert "secret details" not in log_text
		trace("server stored only a safe reject reason and did not log the bad Authorization token")


@pytest.mark.asyncio
async def test_same_server_clients_exchange_messages_without_federation_proxy(tmp_path: Path, trace: Any) -> None:
	cert_path, key_path, ca_path = make_tls(tmp_path)
	port = free_port()
	url = f"https://127.0.0.1:{port}"
	client_a = make_client(tmp_path, "alice", url, "alice-token")
	client_b = make_client(tmp_path, "bob", url, "bob-token")
	identity_a = client_a.export_identity({"username": "alice", "display_name": "Alice"})
	identity_b = client_b.export_identity({"username": "bob", "display_name": "Bob"})
	config = make_server_config(tmp_path, "same-server", url, identity_a, "alice-token", (port,), outbound=set())
	config.hosted_identities["bob"] = identity_b
	config.client_token_hashes["bob"] = hash_client_token("bob-token", allow_weak=True)
	app = create_app(config)
	trace("testing two clients hosted on one enterprise-style local server with direct local routing")
	with RunningServer(app, port, cert_path, key_path, ca_path):
		assert app.state.endpoint.config.federation_policy.outbound_whitelist == set()
		send_ab = await client_a.send_message(identity_b, url, "same server A to B", {"username": "alice"})
		assert send_ab.recipient_trust_state == "untrusted"
		assert app.state.endpoint.queue.count_active("bob") == 1
		assert app.state.endpoint.queue.count_active("alice") == 0
		trace("Alice submitted to Server X; Server X queued ciphertext directly for Bob without outbound federation")
		messages_b = await client_b.receive_messages(limit=1, timeout=5)
		assert [message.body for message in messages_b] == ["same server A to B"]
		assert messages_b[0].sender_metadata == {"username": "alice"}
		assert app.state.endpoint.queue.count_active("bob") == 0
		trace("Bob received and acked Alice's local-server message over WSS")
		reply_identity = {
			"protocol_version": PROTOCOL_VERSION,
			"client_ref": messages_b[0].raw_payload["sender_route"]["client_ref"],
			"public_key_armored": messages_b[0].raw_payload["sender_public_key_armored"],
			"endpoint_fingerprint": messages_b[0].sender_fingerprint,
			"metadata": messages_b[0].sender_metadata,
		}
		await client_b.send_message(reply_identity, url, "same server B to A", {"username": "bob"})
		assert app.state.endpoint.queue.count_active("alice") == 1
		messages_a = await client_a.receive_messages(limit=1, timeout=5)
		assert [message.body for message in messages_a] == ["same server B to A"]
		assert messages_a[0].sender_metadata == {"username": "bob"}
		assert app.state.endpoint.queue.count_active("alice") == 0
		trace("Bob replied through the same server; Alice received and acked the local-server reply")
