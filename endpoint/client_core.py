from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from websockets.asyncio.client import connect

from .crypto import OpenPgpContext, endpoint_fingerprint, verify_detached
from .errors import EndpointError, require
from .protocol import (
	PROTOCOL_VERSION,
	canonical_json_bytes,
	identity_signature_payload,
	message_outer_compare_fields,
	now_iso,
	parse_json_strict,
	validate_encrypted_envelope,
	validate_identity_envelope,
	validate_metadata,
)
from .storage import ClientState
from .transport import httpx_verify_config, wss_ssl_context


@dataclass
class DiscoveryResult:
	identity: dict[str, Any]
	trust_state: str
	route_warning: str | None


@dataclass
class SendResult:
	message_id: str
	recipient_trust_state: str


@dataclass
class ReceivedMessage:
	message_id: str
	body: str
	sender_fingerprint: str
	sender_metadata: dict[str, Any] | None
	sender_trust_state: str
	raw_payload: dict[str, Any]


class EndpointClient:
	def __init__(
		self,
		client_ref: str,
		home_server_url: str,
		auth_token: str,
		state_dir: str | Path,
		key_store_dir: str | Path,
		key_fingerprint: str | None = None,
		verify_tls: str | bool = True,
	):
		self.client_ref = client_ref
		self.home_server_url = home_server_url.rstrip("/")
		self.auth_token = auth_token
		self.openpgp = OpenPgpContext(key_store_dir)
		self.state = ClientState(Path(state_dir))
		self.key_fingerprint = key_fingerprint
		self.verify_tls = verify_tls

	def ensure_identity(self, name: str | None = None, email: str | None = None) -> str:
		if self.key_fingerprint is None:
			if self.openpgp.has_identity_material():
				self.key_fingerprint = self.openpgp.current_fingerprint()
			else:
				self.key_fingerprint = self.openpgp.generate_identity(name, email)
		return self.key_fingerprint

	def require_existing_identity(self) -> str:
		fingerprint = self.key_fingerprint or self.openpgp.current_fingerprint()
		self.openpgp.export_public_key(fingerprint)
		self.key_fingerprint = fingerprint
		return fingerprint

	def public_key_armored(self) -> str:
		return self.openpgp.export_public_key(self.ensure_identity())

	def export_identity(self, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
		validate_metadata(metadata)
		public_key = self.public_key_armored()
		fingerprint = endpoint_fingerprint(public_key)
		identity = {
			"protocol_version": PROTOCOL_VERSION,
			"client_ref": self.client_ref,
			"public_key_armored": public_key,
			"endpoint_fingerprint": fingerprint,
			"metadata": metadata,
		}
		payload = canonical_json_bytes(identity_signature_payload(identity))
		identity["identity_signature"] = self.openpgp.sign_detached(self.ensure_identity(), payload)
		return identity

	def mark_trusted(self, fingerprint: str) -> None:
		self.state.mark_trusted(fingerprint)

	def trust_state(self, fingerprint: str) -> str:
		return self.state.get_trust(fingerprint)

	async def discover(self, peer_server_url: str, peer_client_ref: str) -> DiscoveryResult:
		body = {"client_ref": self.client_ref, "peer_server_url": peer_server_url, "peer_client_ref": peer_client_ref}
		async with httpx.AsyncClient(verify=httpx_verify_config(self.verify_tls), timeout=5.0, follow_redirects=False) as client:
			response = await client.post(
				f"{self.home_server_url}/v1/client/discover",
				json=body,
				headers=self._auth_headers(),
			)
		if response.status_code >= 400:
			raise EndpointError("discover_failed", "identity discovery failed", response.status_code, response.text)
		identity = response.json()
		self.verify_identity(identity)
		self.state.remember_identity(identity)
		route_warning = self.state.remember_route(peer_server_url.rstrip("/"), peer_client_ref, identity["endpoint_fingerprint"])
		return DiscoveryResult(identity, self.trust_state(identity["endpoint_fingerprint"]), route_warning)

	def verify_identity(self, identity: dict[str, Any]) -> None:
		validate_identity_envelope(identity)
		computed = endpoint_fingerprint(identity["public_key_armored"])
		require(computed == identity["endpoint_fingerprint"], "invalid_identity_signature", "identity fingerprint does not match public key")
		payload = canonical_json_bytes(identity_signature_payload(identity))
		try:
			verify_detached(identity["public_key_armored"], payload, identity["identity_signature"])
		except EndpointError as exc:
			raise EndpointError("invalid_identity_signature", "identity signature does not verify", detail=exc.detail) from exc

	async def send_message(
		self,
		recipient_identity: dict[str, Any],
		recipient_server_url: str,
		body: str,
		sender_metadata: dict[str, Any] | None = None,
		message_id: str | None = None,
	) -> SendResult:
		self.verify_recipient_key_material(recipient_identity)
		envelope = self.build_message_envelope(recipient_identity, recipient_server_url, body, sender_metadata, message_id)
		async with httpx.AsyncClient(verify=httpx_verify_config(self.verify_tls), timeout=5.0, follow_redirects=False) as client:
			response = await client.post(
				f"{self.home_server_url}/v1/client/messages",
				json={"client_ref": self.client_ref, "envelope": envelope},
				headers=self._auth_headers(),
			)
		if response.status_code >= 400:
			raise EndpointError("delivery_failed", "message submission failed", response.status_code, response.text)
		return SendResult(envelope["message_id"], self.trust_state(recipient_identity["endpoint_fingerprint"]))

	def build_message_envelope(
		self,
		recipient_identity: dict[str, Any],
		recipient_server_url: str,
		body: str,
		sender_metadata: dict[str, Any] | None = None,
		message_id: str | None = None,
	) -> dict[str, Any]:
		validate_metadata(sender_metadata)
		self.verify_recipient_key_material(recipient_identity)
		message_id = message_id or str(uuid.uuid4())
		sender_public_key = self.public_key_armored()
		sender_fingerprint = endpoint_fingerprint(sender_public_key)
		sender_route = {"server_url": self.home_server_url, "client_ref": self.client_ref}
		recipient_route = {"server_url": recipient_server_url.rstrip("/"), "client_ref": recipient_identity["client_ref"]}
		payload = {
			"protocol_version": PROTOCOL_VERSION,
			"message_id": message_id,
			"body": body,
			"created_at": now_iso(),
			"sender_public_key_armored": sender_public_key,
			"sender_metadata": sender_metadata,
			"sender_fingerprint": sender_fingerprint,
			"recipient_fingerprint": recipient_identity["endpoint_fingerprint"],
			"sender_route": sender_route,
			"recipient_route": recipient_route,
		}
		payload_bytes = canonical_json_bytes(payload)
		signature = self.openpgp.sign_detached(self.ensure_identity(), payload_bytes)
		signed_inner = {
			"protocol_version": PROTOCOL_VERSION,
			"sender_fingerprint": sender_fingerprint,
			"signature_algorithm": "openpgp-detached",
			"payload": payload,
			"signature": signature,
		}
		inner_bytes = canonical_json_bytes(signed_inner)
		ciphertext = self.openpgp.encrypt_to(recipient_identity["public_key_armored"], inner_bytes)
		envelope = {
			"protocol_version": PROTOCOL_VERSION,
			"message_id": message_id,
			"sender_route": sender_route,
			"recipient_route": recipient_route,
			"recipient_fingerprint": recipient_identity["endpoint_fingerprint"],
			"created_at": payload["created_at"],
			"ciphertext_armored": ciphertext,
			"ciphertext_sha256": hashlib.sha256(ciphertext.encode("utf-8")).hexdigest(),
		}
		validate_encrypted_envelope(envelope)
		return envelope

	def verify_recipient_key_material(self, identity: dict[str, Any]) -> None:
		require(isinstance(identity, dict), "invalid_envelope", "recipient identity must be an object")
		for field in ("protocol_version", "client_ref", "public_key_armored", "endpoint_fingerprint"):
			require(isinstance(identity.get(field), str) and identity[field], "invalid_envelope", f"{field} is required")
		require(identity["protocol_version"] == PROTOCOL_VERSION, "invalid_envelope", "unsupported protocol version")
		validate_metadata(identity.get("metadata"))
		computed = endpoint_fingerprint(identity["public_key_armored"])
		require(computed == identity["endpoint_fingerprint"], "invalid_envelope", "recipient fingerprint does not match public key")
		if identity.get("identity_signature"):
			self.verify_identity(identity)

	async def receive_messages(self, limit: int = 1, timeout: float = 5.0) -> list[ReceivedMessage]:
		uri = self._wss_inbox_uri()
		ssl_context = self._ssl_context()
		messages: list[ReceivedMessage] = []
		deferred_frames: deque[dict[str, Any]] = deque()
		deadline = asyncio.get_running_loop().time() + timeout
		async with connect(uri, ssl=ssl_context, additional_headers=self._auth_headers()) as websocket:
			while len(messages) < limit and asyncio.get_running_loop().time() < deadline:
				try:
					frame = deferred_frames.popleft() if deferred_frames else await self._receive_wss_json(websocket, deadline)
				except asyncio.TimeoutError:
					break
				if frame.get("type") != "message":
					continue
				envelope = frame.get("envelope")
				message_id = envelope.get("message_id") if isinstance(envelope, dict) else None
				try:
					message = self.process_envelope(envelope, mark_processed=False)
				except EndpointError as exc:
					reason = exc.code if exc.code in {"malformed_ciphertext", "wrong_recipient", "signature_invalid", "outer_inner_mismatch"} else "invalid_envelope"
					if isinstance(message_id, str):
						await websocket.send(json.dumps({"type": "reject", "message_id": message_id, "reason": reason}))
						await self._wait_for_wss_result(websocket, "reject_result", message_id, deadline, deferred_frames)
					continue
				await websocket.send(json.dumps({"type": "ack", "message_id": message.message_id}))
				if await self._wait_for_wss_result(websocket, "ack_result", message.message_id, deadline, deferred_frames):
					self.state.mark_processed(message.message_id)
					messages.append(message)
		return messages

	async def _receive_wss_json(self, websocket: Any, deadline: float) -> dict[str, Any]:
		remaining = deadline - asyncio.get_running_loop().time()
		if remaining <= 0:
			raise asyncio.TimeoutError
		frame_text = await asyncio.wait_for(websocket.recv(), timeout=max(0.1, remaining))
		return parse_json_strict(frame_text)

	async def _wait_for_wss_result(
		self,
		websocket: Any,
		expected_type: str,
		message_id: str,
		deadline: float,
		deferred_frames: deque[dict[str, Any]],
	) -> bool:
		while asyncio.get_running_loop().time() < deadline:
			try:
				frame = await self._receive_wss_json(websocket, deadline)
			except asyncio.TimeoutError:
				return False
			if frame.get("type") == expected_type and frame.get("message_id") == message_id:
				return frame.get("status") == "ok"
			deferred_frames.append(frame)
		return False

	def process_envelope(self, envelope: Any, mark_processed: bool = True) -> ReceivedMessage:
		validate_encrypted_envelope(envelope)
		if self.state.has_processed(envelope["message_id"]):
			raise EndpointError("duplicate_message_id", "message was already processed")
		try:
			inner = parse_json_strict(self.openpgp.decrypt(envelope["ciphertext_armored"]))
		except EndpointError as exc:
			raise EndpointError("malformed_ciphertext", "ciphertext could not be decrypted", detail=exc.detail) from exc
		require(isinstance(inner, dict), "malformed_ciphertext", "inner message is invalid")
		payload = inner.get("payload")
		require(isinstance(payload, dict), "malformed_ciphertext", "inner payload is invalid")
		require(inner.get("protocol_version") == PROTOCOL_VERSION, "malformed_ciphertext", "inner protocol version is invalid")
		require(inner.get("signature_algorithm") == "openpgp-detached", "signature_invalid", "unsupported signature algorithm")
		mismatches = message_outer_compare_fields(envelope, payload)
		require(not mismatches, "outer_inner_mismatch", "outer and inner fields do not match", detail=",".join(mismatches))
		sender_public_key = payload.get("sender_public_key_armored")
		require(isinstance(sender_public_key, str) and sender_public_key, "signature_invalid", "sender public key is missing")
		sender_fingerprint = endpoint_fingerprint(sender_public_key)
		require(sender_fingerprint == payload.get("sender_fingerprint"), "signature_invalid", "sender fingerprint does not match public key")
		require(sender_fingerprint == inner.get("sender_fingerprint"), "signature_invalid", "signed message sender mismatch")
		payload_bytes = canonical_json_bytes(payload)
		verify_detached(sender_public_key, payload_bytes, inner.get("signature", ""))
		own_fingerprint = endpoint_fingerprint(self.public_key_armored())
		require(payload.get("recipient_fingerprint") == own_fingerprint, "wrong_recipient", "message is not addressed to this identity")
		self.state.remember_route(payload["sender_route"]["server_url"], payload["sender_route"]["client_ref"], sender_fingerprint)
		sender_identity = {
			"protocol_version": PROTOCOL_VERSION,
			"client_ref": payload["sender_route"]["client_ref"],
			"public_key_armored": sender_public_key,
			"endpoint_fingerprint": sender_fingerprint,
			"metadata": payload.get("sender_metadata"),
			"identity_signature": "",
		}
		self.state.remember_identity(sender_identity)
		if mark_processed:
			self.state.mark_processed(envelope["message_id"])
		return ReceivedMessage(
			message_id=envelope["message_id"],
			body=payload["body"],
			sender_fingerprint=sender_fingerprint,
			sender_metadata=payload.get("sender_metadata"),
			sender_trust_state=self.trust_state(sender_fingerprint),
			raw_payload=payload,
		)

	def _auth_headers(self) -> dict[str, str]:
		return {"Authorization": f"Bearer {self.auth_token}"}

	def _wss_inbox_uri(self) -> str:
		parsed = urlparse(self.home_server_url)
		host = parsed.netloc
		return f"wss://{host}/v1/client/{self.client_ref}/inbox"

	def _ssl_context(self):
		return wss_ssl_context(self.verify_tls)
