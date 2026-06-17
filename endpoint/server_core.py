from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse

from .credentials import validate_client_token_hash, verify_client_token
from .crypto import endpoint_fingerprint, verify_detached
from .errors import EndpointError, require
from .protocol import (
	ProtocolLimits,
	canonical_json_bytes,
	identity_signature_payload,
	validate_encrypted_envelope,
	validate_identity_envelope,
)
from .storage import MessageQueue, ReplayStore, StructuredLog
from .transport import FederationPolicy, httpx_verify_config, validate_https_url

SAFE_REJECT_REASONS = {"malformed_ciphertext", "wrong_recipient", "signature_invalid", "outer_inner_mismatch", "invalid_envelope"}


@dataclass
class ServerConfig:
	server_url: str
	state_dir: Path
	hosted_identities: dict[str, dict[str, Any]]
	client_token_hashes: dict[str, str]
	ca_bundle: str | bool = True
	federation_policy: FederationPolicy = field(default_factory=FederationPolicy)
	lease_seconds: int = 2
	rejected_policy: str = "drop"
	debug_errors: bool = False
	verify_hosted_identity_signatures: bool = True


class ServerState:
	def __init__(self, config: ServerConfig):
		self.config = config
		self.config.state_dir.mkdir(parents=True, exist_ok=True)
		self.queue = MessageQueue(self.config.state_dir, self.config.rejected_policy)
		self.replay = ReplayStore(self.config.state_dir)
		self.log = StructuredLog(self.config.state_dir / "logs" / "structured.jsonl")
		self._validate_config()

	def _validate_config(self) -> None:
		require(set(self.config.client_token_hashes) == set(self.config.hosted_identities), "invalid_config", "client token hashes must match hosted identities")
		for client_ref, verifier in self.config.client_token_hashes.items():
			require(isinstance(client_ref, str) and client_ref != "", "invalid_config", "client token client_ref is invalid")
			validate_client_token_hash(verifier)
		for client_ref, identity in self.config.hosted_identities.items():
			validate_identity_envelope(identity)
			require(identity["client_ref"] == client_ref, "invalid_envelope", "hosted identity client_ref mismatch")
			computed = endpoint_fingerprint(identity["public_key_armored"])
			require(computed == identity["endpoint_fingerprint"], "invalid_envelope", "hosted identity fingerprint mismatch")
			if self.config.verify_hosted_identity_signatures:
				payload = canonical_json_bytes(identity_signature_payload(identity))
				verify_detached(identity["public_key_armored"], payload, identity["identity_signature"])

	def authenticate_client(self, client_ref: str, authorization: str | None) -> None:
		require(isinstance(client_ref, str) and client_ref != "", "unauthorized", "invalid client credentials", 401)
		require(isinstance(authorization, str), "unauthorized", "invalid client credentials", 401)
		require(authorization.startswith("Bearer "), "unauthorized", "invalid client credentials", 401)
		token = authorization.removeprefix("Bearer ")
		require(token != "" and " " not in token, "unauthorized", "invalid client credentials", 401)
		verifier = self.config.client_token_hashes.get(client_ref)
		require(verifier is not None and verify_client_token(token, verifier), "unauthorized", "invalid client credentials", 401)

	def local_identity(self, client_ref: str) -> dict[str, Any]:
		identity = self.config.hosted_identities.get(client_ref)
		require(identity is not None, "unknown_recipient", "unknown local identity", 404)
		return identity

	def accept_envelope_for_local(self, envelope: dict[str, Any]) -> None:
		validate_encrypted_envelope(envelope, ProtocolLimits())
		recipient = envelope["recipient_route"]["client_ref"]
		self.local_identity(recipient)
		scope = f"{recipient}"
		require(self.replay.remember(scope, envelope["message_id"]), "duplicate_message_id", "duplicate message id", 409)
		require(self.queue.add(recipient, envelope), "duplicate_message_id", "duplicate message id", 409)
		self.log.write("message_queued", client_ref=recipient, message_id=envelope["message_id"])

	def is_local_server_url(self, server_url: str) -> bool:
		return _normalize_configured_url(server_url) == _normalize_configured_url(self.config.server_url)


def create_app(config: ServerConfig) -> FastAPI:
	state = ServerState(config)
	app = FastAPI()
	app.state.endpoint = state

	@app.exception_handler(EndpointError)
	async def endpoint_exception_handler(_: Request, exc: EndpointError) -> JSONResponse:
		state.log.write("error", code=exc.code)
		return JSONResponse(exc.safe_body(config.debug_errors), status_code=exc.status_code)

	@app.get("/v1/health")
	async def health() -> dict[str, str]:
		return {"status": "ok"}

	@app.post("/v1/client/discover")
	async def client_discover(request: Request) -> Any:
		body = await _request_json_object(request)
		client_ref = body.get("client_ref")
		state.authenticate_client(client_ref, request.headers.get("authorization"))
		peer_server_url = validate_https_url(body.get("peer_server_url", ""), config.federation_policy, "outbound")
		peer_client_ref = body.get("peer_client_ref")
		require(isinstance(peer_client_ref, str) and peer_client_ref, "invalid_envelope", "peer_client_ref is required")
		try:
			async with httpx.AsyncClient(verify=httpx_verify_config(config.ca_bundle), timeout=5.0, follow_redirects=False) as client:
				response = await client.get(f"{peer_server_url}/v1/federation/identity/{peer_client_ref}")
		except httpx.RequestError as exc:
			raise EndpointError("delivery_failed", "identity discovery failed", 502, detail=type(exc).__name__) from exc
		_require_success_response(response, "identity discovery failed")
		identity = _response_json_object(response, ProtocolLimits().max_identity_bytes, "identity response is too large")
		validate_identity_envelope(identity)
		state.log.write("identity_discovered", client_ref=client_ref, peer_client_ref=peer_client_ref)
		return identity

	@app.post("/v1/client/messages")
	async def client_messages(request: Request) -> dict[str, str]:
		body = await _request_json_object(request)
		client_ref = body.get("client_ref")
		state.authenticate_client(client_ref, request.headers.get("authorization"))
		envelope = body.get("envelope")
		validate_encrypted_envelope(envelope)
		if state.is_local_server_url(envelope["recipient_route"]["server_url"]):
			state.accept_envelope_for_local(envelope)
			state.log.write("message_routed_local", client_ref=client_ref, message_id=envelope["message_id"])
			return {"status": "queued", "message_id": envelope["message_id"]}
		destination = validate_https_url(envelope["recipient_route"]["server_url"], config.federation_policy, "outbound")
		try:
			async with httpx.AsyncClient(verify=httpx_verify_config(config.ca_bundle), timeout=5.0, follow_redirects=False) as client:
				response = await client.post(f"{destination}/v1/federation/messages", json=envelope)
		except httpx.RequestError as exc:
			raise EndpointError("delivery_failed", "federation delivery failed", 502, detail=type(exc).__name__) from exc
		_require_success_response(response, "federation delivery failed")
		state.log.write("message_proxied", client_ref=client_ref, message_id=envelope["message_id"])
		return {"status": "proxied", "message_id": envelope["message_id"]}

	@app.get("/v1/federation/identity/{client_ref}")
	async def federation_identity(client_ref: str, request: Request) -> Any:
		if config.federation_policy.inbound_whitelist:
			peer = request.headers.get("endpoint-peer-url")
			require(peer is not None, "forbidden_peer", "peer identity is required", 403)
			validate_https_url(peer, config.federation_policy, "inbound")
		return state.local_identity(client_ref)

	@app.post("/v1/federation/messages")
	async def federation_messages(request: Request) -> dict[str, str]:
		envelope = await _request_json_object(request)
		if config.federation_policy.inbound_whitelist:
			validate_https_url(envelope.get("sender_route", {}).get("server_url", ""), config.federation_policy, "inbound")
		state.accept_envelope_for_local(envelope)
		return {"status": "queued", "message_id": envelope["message_id"]}

	@app.websocket("/v1/client/{client_ref}/inbox")
	async def websocket_inbox(websocket: WebSocket, client_ref: str) -> None:
		try:
			state.authenticate_client(client_ref, websocket.headers.get("authorization"))
		except EndpointError:
			await websocket.close(code=1008)
			return
		await websocket.accept()
		state.log.write("wss_connected", client_ref=client_ref)
		try:
			while True:
				await _deliver_available(websocket, state, client_ref)
				frame = await _receive_wss_frame(websocket)
				if frame is None:
					continue
				frame_type = frame.get("type")
				message_id = frame.get("message_id")
				if not isinstance(message_id, str):
					continue
				if frame_type == "ack":
					if state.queue.ack(client_ref, message_id):
						state.log.write("message_acked", client_ref=client_ref, message_id=message_id)
				elif frame_type == "reject":
					reason = _safe_reject_reason(frame.get("reason"))
					if state.queue.reject(client_ref, message_id, reason):
						state.log.write("message_rejected", client_ref=client_ref, message_id=message_id, reason=reason)
		except WebSocketDisconnect:
			state.log.write("wss_disconnected", client_ref=client_ref)

	return app


async def _deliver_available(websocket: WebSocket, state: ServerState, client_ref: str) -> None:
	for record in state.queue.deliverable(client_ref):
		leased = state.queue.lease(client_ref, record["message_id"], state.config.lease_seconds)
		if leased is None:
			continue
		await websocket.send_json({"type": "message", "envelope": leased["envelope"]})
		state.log.write("message_leased", client_ref=client_ref, message_id=record["message_id"])


async def _receive_wss_frame(websocket: WebSocket) -> dict[str, Any] | None:
	try:
		frame = await asyncio.wait_for(websocket.receive_json(), timeout=0.2)
	except asyncio.TimeoutError:
		return None
	except WebSocketDisconnect:
		raise
	except Exception:
		return None
	if not isinstance(frame, dict):
		return None
	return frame


def _safe_reject_reason(reason: Any) -> str:
	if isinstance(reason, str) and reason in SAFE_REJECT_REASONS:
		return reason
	return "invalid_envelope"


def _require_success_response(response: httpx.Response, message: str) -> None:
	require(200 <= response.status_code < 300, "delivery_failed", message, 502)


def _response_json_object(response: httpx.Response, max_size: int, size_message: str) -> dict[str, Any]:
	require(len(response.content) <= max_size, "metadata_too_large", size_message)
	try:
		body = response.json()
	except Exception as exc:
		raise EndpointError("invalid_envelope", "peer returned invalid JSON", 400, detail=type(exc).__name__) from exc
	require(isinstance(body, dict), "invalid_envelope", "peer JSON response must be an object")
	return body


def _normalize_configured_url(url: str) -> str:
	return url.rstrip("/").lower()


async def _request_json_object(request: Request) -> dict[str, Any]:
	try:
		body = await request.json()
	except Exception as exc:
		raise EndpointError("invalid_envelope", "invalid JSON request body", 400, detail=type(exc).__name__) from exc
	require(isinstance(body, dict), "invalid_envelope", "JSON request body must be an object")
	return body
