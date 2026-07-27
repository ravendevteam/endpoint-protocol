from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx
from websockets.asyncio.client import connect

from .contact import normalize_contact, validate_endpoint_fingerprint
from .crypto import OpenPgpContext, endpoint_fingerprint, verify_detached
from .errors import EndpointError, require
from .protocol import (
	PROTOCOL_VERSION,
	canonical_json_bytes,
	delivery_envelope_uses_content_reference,
	delivery_outer_compare_fields,
	identity_signature_payload,
	now_iso,
	parse_json_strict,
	signed_content_hash,
	validate_content_object,
	validate_delivery_claim,
	validate_delivery_envelope,
	validate_identity_envelope,
	validate_metadata,
	validate_signed_content,
)
from .storage import ClientOutbox, ClientState
from .transport import httpx_verify_config, normalize_server_url, wss_ssl_context

IDENTITY_SIGNATURE_HINT = "Sync system clocks, regenerate the identity or enrollment bundle, and retry."
CONTENT_RETENTION_DAYS = 30


@dataclass
class DiscoveryResult:
	identity: dict[str, Any]
	trust_state: str
	route_warning: str | None
	pin_state: str | None = None


@dataclass
class SendResult:
	message_id: str
	recipient_trust_state: str
	content_id: str | None = None


@dataclass
class RecipientSpec:
	identity: dict[str, Any]
	server_url: str
	role: str = "to"
	message_id: str | None = None


@dataclass
class DeliveryResult:
	message_id: str
	content_id: str
	recipient_route: dict[str, str]
	recipient_role: str
	recipient_trust_state: str
	status: str
	error_code: str | None = None


@dataclass
class FanoutSendResult:
	content_id: str
	deliveries: list[DeliveryResult]


@dataclass
class ReceivedMessage:
	message_id: str
	content_id: str
	content_type: str
	content: Any
	delivery_role: str
	body: str | None
	sender_fingerprint: str
	sender_metadata: dict[str, Any] | None
	sender_trust_state: str
	raw_payload: dict[str, Any]
	raw_delivery_claim: dict[str, Any]


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
		self.home_server_url = normalize_server_url(home_server_url)
		self.auth_token = auth_token
		self.openpgp = OpenPgpContext(key_store_dir)
		self.state = ClientState(Path(state_dir))
		self.outbox = ClientOutbox(Path(state_dir))
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

	def import_contact_pin(self, contact: dict[str, Any]) -> dict[str, Any]:
		contact = self.validate_contact_pin(contact)
		self.state.remember_contact_pin(contact["server_url"], contact["client_ref"], contact["endpoint_fingerprint"])
		public_identity = contact.get("public_identity")
		if public_identity is not None:
			self.state.remember_identity(public_identity)
		return contact

	def validate_contact_pin(self, contact: dict[str, Any]) -> dict[str, Any]:
		contact = normalize_contact(contact)
		public_identity = contact.get("public_identity")
		if public_identity is not None:
			self.verify_identity(public_identity)
		return contact

	async def discover(self, peer_server_url: str, peer_client_ref: str, expected_fingerprint: str | None = None) -> DiscoveryResult:
		peer_server_url = normalize_server_url(peer_server_url)
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
		pin_state = None
		if expected_fingerprint is not None:
			expected_fingerprint = validate_endpoint_fingerprint(expected_fingerprint)
			require(
				identity["endpoint_fingerprint"] == expected_fingerprint,
				"contact_fingerprint_mismatch",
				"discovered identity does not match contact fingerprint",
			)
			self.state.remember_contact_pin(peer_server_url, peer_client_ref, expected_fingerprint)
			pin_state = "matched"
		self.state.remember_identity(identity)
		route_warning = self.state.remember_route(peer_server_url, peer_client_ref, identity["endpoint_fingerprint"])
		return DiscoveryResult(identity, self.trust_state(identity["endpoint_fingerprint"]), route_warning, pin_state)

	def verify_identity(self, identity: dict[str, Any]) -> None:
		validate_identity_envelope(identity)
		computed = endpoint_fingerprint(identity["public_key_armored"])
		require(computed == identity["endpoint_fingerprint"], "invalid_identity_signature", "identity fingerprint does not match public key")
		payload = canonical_json_bytes(identity_signature_payload(identity))
		try:
			verify_detached(identity["public_key_armored"], payload, identity["identity_signature"])
		except EndpointError as exc:
			raise EndpointError("invalid_identity_signature", "identity signature does not verify", detail=exc.detail, hint=IDENTITY_SIGNATURE_HINT) from exc

	async def send_message(
		self,
		recipient_identity: dict[str, Any],
		recipient_server_url: str,
		body: str,
		sender_metadata: dict[str, Any] | None = None,
		message_id: str | None = None,
	) -> SendResult:
		recipient = RecipientSpec(recipient_identity, recipient_server_url, "to", message_id)
		result = await self.send_message_fanout([recipient], body, sender_metadata)
		delivery = result.deliveries[0]
		if delivery.status != "queued":
			raise EndpointError("delivery_failed", "message submission failed", detail=delivery.error_code)
		return SendResult(delivery.message_id, delivery.recipient_trust_state, result.content_id)

	async def send_message_fanout(
		self,
		recipients: list[RecipientSpec],
		body: str,
		sender_metadata: dict[str, Any] | None = None,
		content_id: str | None = None,
	) -> FanoutSendResult:
		recipients = self._validate_recipient_specs(recipients)
		visible_to = [self._route_for_spec(spec) for spec in recipients if spec.role == "to"]
		visible_cc = [self._route_for_spec(spec) for spec in recipients if spec.role == "cc"]
		content = {
			"body": body,
			"sender_metadata": sender_metadata,
			"visible_to": visible_to,
			"visible_cc": visible_cc,
		}
		signed_content = self.build_signed_content("message", content, content_id=content_id)
		return await self.send_content(signed_content, recipients)

	async def send_content(self, signed_content: dict[str, Any], recipients: list[RecipientSpec]) -> FanoutSendResult:
		return await self._send_content_reference(signed_content, recipients)

	async def _send_content_reference(self, signed_content: dict[str, Any], recipients: list[RecipientSpec]) -> FanoutSendResult:
		recipients = self._validate_recipient_specs(recipients)
		content_ciphertext = self.openpgp.encrypt_to_many(
			[spec.identity["public_key_armored"] for spec in recipients],
			canonical_json_bytes(signed_content),
		)
		content_object = self.build_content_object(signed_content, content_ciphertext)
		envelopes = self.build_delivery_envelopes(
			signed_content,
			recipients,
			content_ciphertext=content_ciphertext,
			inline_content=False,
		)
		content_id = signed_content["content_id"]
		self.outbox.save(content_object, envelopes)
		results: list[DeliveryResult] = []
		async with httpx.AsyncClient(verify=httpx_verify_config(self.verify_tls), timeout=5.0, follow_redirects=False) as client:
			try:
				response = await client.post(
					f"{self.home_server_url}/v1/client/content",
					json={"client_ref": self.client_ref, "content": content_object},
					headers=self._auth_headers(),
				)
				if response.status_code >= 400:
					raise EndpointError("content_upload_failed", "content upload failed", response.status_code, response.text)
			except (EndpointError, httpx.RequestError) as exc:
				code = exc.code if isinstance(exc, EndpointError) else "content_upload_failed"
				for envelope, recipient in zip(envelopes, recipients, strict=True):
					self.outbox.mark(envelope["message_id"], "failed", code)
					results.append(self._delivery_result(envelope, recipient, "failed", code))
				return FanoutSendResult(content_id, results)
			for envelope, recipient in zip(envelopes, recipients, strict=True):
				results.append(await self._submit_envelope(client, envelope, recipient))
		return FanoutSendResult(content_id, results)

	async def retry_outbox(self, limit: int = 50) -> FanoutSendResult | None:
		batch = self.outbox.pending_batch(limit)
		if batch is None:
			return None
		content_object, envelopes = batch
		async with httpx.AsyncClient(verify=httpx_verify_config(self.verify_tls), timeout=5.0, follow_redirects=False) as client:
			try:
				response = await client.post(
					f"{self.home_server_url}/v1/client/content",
					json={"client_ref": self.client_ref, "content": content_object},
					headers=self._auth_headers(),
				)
				if response.status_code >= 400:
					raise EndpointError("content_upload_failed", "content upload failed", response.status_code, response.text)
			except (EndpointError, httpx.RequestError) as exc:
				code = exc.code if isinstance(exc, EndpointError) else "delivery_failed"
				return FanoutSendResult(content_object["content_id"], [self._delivery_result(envelope, None, "failed", code) for envelope in envelopes])
			results = []
			for envelope in envelopes:
				results.append(await self._submit_envelope(client, envelope, None))
			return FanoutSendResult(content_object["content_id"], results)

	async def _submit_envelope(self, client: httpx.AsyncClient, envelope: dict[str, Any], recipient: RecipientSpec | None) -> DeliveryResult:
		try:
			response = await client.post(
				f"{self.home_server_url}/v1/client/messages",
				json={"client_ref": self.client_ref, "envelope": envelope},
				headers=self._auth_headers(),
			)
			if response.status_code >= 400:
				raise EndpointError("delivery_failed", "message submission failed", response.status_code, response.text)
			self.outbox.mark(envelope["message_id"], "queued", None)
			return self._delivery_result(envelope, recipient, "queued", None)
		except EndpointError as exc:
			self.outbox.mark(envelope["message_id"], "failed", exc.code)
			return self._delivery_result(envelope, recipient, "failed", exc.code)
		except httpx.RequestError:
			self.outbox.mark(envelope["message_id"], "failed", "delivery_failed")
			return self._delivery_result(envelope, recipient, "failed", "delivery_failed")

	def _delivery_result(self, envelope: dict[str, Any], recipient: RecipientSpec | None, status: str, error_code: str | None) -> DeliveryResult:
		fingerprint = recipient.identity["endpoint_fingerprint"] if recipient is not None else envelope["recipient_fingerprint"]
		return DeliveryResult(
			envelope["message_id"],
			envelope["content_id"],
			envelope["recipient_route"],
			envelope["recipient_role"],
			self.trust_state(fingerprint),
			status,
			error_code,
		)

	def build_content_object(
		self,
		signed_content: dict[str, Any],
		content_ciphertext: str,
		*,
		expires_at: str | None = None,
	) -> dict[str, Any]:
		validate_signed_content(signed_content)
		content_object = {
			"protocol_version": PROTOCOL_VERSION,
			"content_id": signed_content["content_id"],
			"content_sha256": signed_content_hash(signed_content),
			"ciphertext_armored": content_ciphertext,
			"ciphertext_sha256": hashlib.sha256(content_ciphertext.encode("utf-8")).hexdigest(),
			"size_bytes": len(canonical_json_bytes(signed_content)),
			"created_at": signed_content["payload"]["created_at"],
			"expires_at": expires_at or (datetime.now(UTC) + timedelta(days=CONTENT_RETENTION_DAYS)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
		}
		validate_content_object(content_object)
		return content_object

	def build_signed_content(
		self,
		content_type: str,
		content: Any,
		*,
		content_id: str | None = None,
		created_at: str | None = None,
	) -> dict[str, Any]:
		sender_public_key = self.public_key_armored()
		sender_fingerprint = endpoint_fingerprint(sender_public_key)
		payload = {
			"protocol_version": PROTOCOL_VERSION,
			"content_id": content_id or str(uuid.uuid4()),
			"content_type": content_type,
			"created_at": created_at or now_iso(),
			"sender_public_key_armored": sender_public_key,
			"sender_fingerprint": sender_fingerprint,
			"sender_route": {"server_url": self.home_server_url, "client_ref": self.client_ref},
			"content": content,
		}
		if content_type == "message" and isinstance(content, dict):
			payload["body"] = content.get("body")
			payload["sender_metadata"] = content.get("sender_metadata")
		signed_content = {
			"protocol_version": PROTOCOL_VERSION,
			"content_id": payload["content_id"],
			"sender_fingerprint": sender_fingerprint,
			"signature_algorithm": "openpgp-detached",
			"payload": payload,
			"signature": self.openpgp.sign_detached(self.ensure_identity(), canonical_json_bytes(payload)),
		}
		validate_signed_content(signed_content)
		return signed_content

	def build_delivery_envelopes(
		self,
		signed_content: dict[str, Any],
		recipients: list[RecipientSpec],
		*,
		content_ciphertext: str | None = None,
		inline_content: bool = True,
	) -> list[dict[str, Any]]:
		validate_signed_content(signed_content)
		recipients = self._validate_recipient_specs(recipients)
		sender_public_key = self.public_key_armored()
		sender_fingerprint = endpoint_fingerprint(sender_public_key)
		payload = signed_content["payload"]
		require(payload["sender_fingerprint"] == sender_fingerprint, "signature_invalid", "signed content is not owned by this sender")
		content_hash = signed_content_hash(signed_content)
		if content_ciphertext is None:
			content_ciphertext = self.openpgp.encrypt_to_many(
				[spec.identity["public_key_armored"] for spec in recipients],
				canonical_json_bytes(signed_content),
			)
		content_ciphertext_hash = hashlib.sha256(content_ciphertext.encode("utf-8")).hexdigest()
		sender_route = {"server_url": self.home_server_url, "client_ref": self.client_ref}
		envelopes: list[dict[str, Any]] = []
		for spec in recipients:
			recipient_route = self._route_for_spec(spec)
			message_id = spec.message_id or str(uuid.uuid4())
			claim_payload = {
				"protocol_version": PROTOCOL_VERSION,
				"message_id": message_id,
				"content_id": signed_content["content_id"],
				"content_sha256": content_hash,
				"created_at": payload["created_at"],
				"sender_route": sender_route,
				"recipient_route": recipient_route,
				"recipient_fingerprint": spec.identity["endpoint_fingerprint"],
				"recipient_role": spec.role,
				"sender_fingerprint": sender_fingerprint,
			}
			claim = {
				"protocol_version": PROTOCOL_VERSION,
				"sender_fingerprint": sender_fingerprint,
				"signature_algorithm": "openpgp-detached",
				"payload": claim_payload,
				"signature": self.openpgp.sign_detached(self.ensure_identity(), canonical_json_bytes(claim_payload)),
			}
			validate_delivery_claim(claim)
			delivery_ciphertext = self.openpgp.encrypt_to(spec.identity["public_key_armored"], canonical_json_bytes(claim))
			envelope = {
				"protocol_version": PROTOCOL_VERSION,
				"message_id": message_id,
				"content_id": signed_content["content_id"],
				"content_sha256": content_hash,
				"sender_route": sender_route,
				"recipient_route": recipient_route,
				"recipient_fingerprint": spec.identity["endpoint_fingerprint"],
				"recipient_role": spec.role,
				"created_at": payload["created_at"],
				"delivery_ciphertext_armored": delivery_ciphertext,
				"delivery_ciphertext_sha256": hashlib.sha256(delivery_ciphertext.encode("utf-8")).hexdigest(),
			}
			if inline_content:
				envelope["ciphertext_armored"] = content_ciphertext
				envelope["ciphertext_sha256"] = content_ciphertext_hash
			else:
				envelope["content_ref"] = {"content_id": signed_content["content_id"], "content_sha256": content_hash}
			validate_delivery_envelope(envelope)
			envelopes.append(envelope)
		return envelopes

	def build_message_envelope(
		self,
		recipient_identity: dict[str, Any],
		recipient_server_url: str,
		body: str,
		sender_metadata: dict[str, Any] | None = None,
		message_id: str | None = None,
	) -> dict[str, Any]:
		result = self._build_message_content_and_envelopes(
			[RecipientSpec(recipient_identity, recipient_server_url, "to", message_id)],
			body,
			sender_metadata,
		)
		return result[0]

	def _build_message_content_and_envelopes(
		self,
		recipients: list[RecipientSpec],
		body: str,
		sender_metadata: dict[str, Any] | None,
	) -> list[dict[str, Any]]:
		recipients = self._validate_recipient_specs(recipients)
		content = {
			"body": body,
			"sender_metadata": sender_metadata,
			"visible_to": [self._route_for_spec(spec) for spec in recipients if spec.role == "to"],
			"visible_cc": [self._route_for_spec(spec) for spec in recipients if spec.role == "cc"],
		}
		signed_content = self.build_signed_content("message", content)
		return self.build_delivery_envelopes(signed_content, recipients)

	def _validate_recipient_specs(self, recipients: list[RecipientSpec]) -> list[RecipientSpec]:
		require(isinstance(recipients, list) and recipients, "invalid_envelope", "at least one recipient is required")
		seen: set[tuple[str, str]] = set()
		seen_fingerprints: set[str] = set()
		for spec in recipients:
			require(isinstance(spec, RecipientSpec), "invalid_envelope", "recipient must be a RecipientSpec")
			require(spec.role in {"to", "cc", "bcc"}, "invalid_envelope", "recipient role is invalid")
			self.verify_recipient_key_material(spec.identity)
			route = self._route_for_spec(spec)
			key = (route["server_url"], route["client_ref"])
			require(key not in seen, "invalid_envelope", "recipient route is duplicated")
			require(spec.identity["endpoint_fingerprint"] not in seen_fingerprints, "invalid_envelope", "recipient identity is duplicated")
			seen.add(key)
			seen_fingerprints.add(spec.identity["endpoint_fingerprint"])
		return recipients

	@staticmethod
	def _route_for_spec(spec: RecipientSpec) -> dict[str, str]:
		return {"server_url": normalize_server_url(spec.server_url), "client_ref": spec.identity["client_ref"]}

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
					content_object = await self._fetch_content_object(envelope) if delivery_envelope_uses_content_reference(envelope) else None
					message = self.process_envelope(envelope, mark_processed=False, content_object=content_object)
				except EndpointError as exc:
					reason = exc.code if exc.code in {
						"malformed_ciphertext",
						"wrong_recipient",
						"signature_invalid",
						"outer_inner_mismatch",
						"delivery_claim_invalid",
						"content_hash_mismatch",
						"content_unavailable",
						"content_expired",
					} else "invalid_envelope"
					if isinstance(message_id, str):
						await websocket.send(json.dumps({"type": "reject", "message_id": message_id, "reason": reason}))
						await self._wait_for_wss_result(websocket, "reject_result", message_id, deadline, deferred_frames)
					continue
				await websocket.send(json.dumps({"type": "ack", "message_id": message.message_id}))
				if await self._wait_for_wss_result(websocket, "ack_result", message.message_id, deadline, deferred_frames):
					self.state.mark_processed(message.message_id)
					messages.append(message)
		return messages

	async def _fetch_content_object(self, envelope: dict[str, Any]) -> dict[str, Any]:
		try:
			async with httpx.AsyncClient(verify=httpx_verify_config(self.verify_tls), timeout=5.0, follow_redirects=False) as client:
				response = await client.get(
					f"{self.home_server_url}/v1/client/content/{envelope['content_id']}",
					headers={**self._auth_headers(), "x-endpoint-client-ref": self.client_ref},
				)
		except httpx.RequestError as exc:
			raise EndpointError("content_unavailable", "referenced content could not be fetched", 503, detail=type(exc).__name__) from exc
		if response.status_code >= 400:
			code = "content_expired" if response.status_code == 410 else "content_unavailable"
			raise EndpointError(code, "referenced content is not available", response.status_code)
		try:
			content_object = parse_json_strict(response.content)
		except EndpointError as exc:
			raise EndpointError("content_unavailable", "content response is invalid", detail=exc.detail) from exc
		validate_content_object(content_object)
		require(content_object["content_id"] == envelope["content_id"], "content_hash_mismatch", "fetched content id does not match envelope")
		require(content_object["content_sha256"] == envelope["content_sha256"], "content_hash_mismatch", "fetched content hash does not match envelope")
		return content_object

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

	def process_envelope(
		self,
		envelope: Any,
		mark_processed: bool = True,
		content_object: dict[str, Any] | None = None,
	) -> ReceivedMessage:
		validate_delivery_envelope(envelope)
		if self.state.has_processed(envelope["message_id"]):
			raise EndpointError("duplicate_message_id", "message was already processed")
		try:
			claim = parse_json_strict(self.openpgp.decrypt(envelope["delivery_ciphertext_armored"]))
		except EndpointError as exc:
			raise EndpointError("malformed_ciphertext", "delivery claim could not be decrypted", detail=exc.detail) from exc
		content_ciphertext = envelope.get("ciphertext_armored")
		if delivery_envelope_uses_content_reference(envelope):
			require(content_object is not None, "content_unavailable", "referenced content must be fetched before processing", 503)
			validate_content_object(content_object)
			require(content_object["content_id"] == envelope["content_id"], "content_hash_mismatch", "content id does not match fetched content")
			require(content_object["content_sha256"] == envelope["content_sha256"], "content_hash_mismatch", "content hash does not match fetched content")
			content_ciphertext = content_object["ciphertext_armored"]
		try:
			content = parse_json_strict(self.openpgp.decrypt(content_ciphertext))
		except EndpointError as exc:
			raise EndpointError("malformed_ciphertext", "content could not be decrypted", detail=exc.detail) from exc
		if isinstance(claim, dict) and claim.get("protocol_version") != PROTOCOL_VERSION:
			raise EndpointError("outer_inner_mismatch", "delivery claim protocol version does not match envelope")
		if isinstance(content, dict) and isinstance(content.get("payload"), dict) and content["payload"].get("protocol_version") != PROTOCOL_VERSION:
			raise EndpointError("outer_inner_mismatch", "signed content protocol version does not match envelope")
		validate_delivery_claim(claim)
		validate_signed_content(content)
		content_payload = content["payload"]
		sender_public_key = content_payload.get("sender_public_key_armored")
		require(isinstance(sender_public_key, str) and sender_public_key, "signature_invalid", "sender public key is missing")
		sender_fingerprint = endpoint_fingerprint(sender_public_key)
		require(sender_fingerprint == content_payload.get("sender_fingerprint"), "signature_invalid", "sender fingerprint does not match public key")
		require(sender_fingerprint == content.get("sender_fingerprint"), "signature_invalid", "signed content sender mismatch")
		verify_detached(sender_public_key, canonical_json_bytes(content_payload), content.get("signature", ""))
		claim_payload = claim["payload"]
		require(sender_fingerprint == claim.get("sender_fingerprint"), "signature_invalid", "delivery claim sender mismatch")
		require(sender_fingerprint == claim_payload.get("sender_fingerprint"), "signature_invalid", "delivery claim payload sender mismatch")
		verify_detached(sender_public_key, canonical_json_bytes(claim_payload), claim.get("signature", ""))
		own_fingerprint = endpoint_fingerprint(self.public_key_armored())
		require(envelope["recipient_fingerprint"] == own_fingerprint, "wrong_recipient", "message is not addressed to this identity")
		require(signed_content_hash(content) == envelope["content_sha256"], "outer_inner_mismatch", "signed content hash does not match delivery envelope")
		require(claim_payload["content_sha256"] == envelope["content_sha256"], "outer_inner_mismatch", "delivery claim content hash does not match envelope")
		require(content_payload["sender_route"] == claim_payload["sender_route"], "outer_inner_mismatch", "signed content and delivery claim sender routes do not match")
		mismatches = delivery_outer_compare_fields(envelope, claim_payload)
		require(not mismatches, "outer_inner_mismatch", "outer and delivery claim fields do not match", detail=",".join(mismatches))
		require(claim_payload.get("recipient_fingerprint") == own_fingerprint, "wrong_recipient", "message is not addressed to this identity")
		self._validate_visible_recipient_role(content_payload, claim_payload)
		self.state.remember_route(claim_payload["sender_route"]["server_url"], claim_payload["sender_route"]["client_ref"], sender_fingerprint)
		content_data = content_payload["content"]
		sender_metadata = content_data.get("sender_metadata") if isinstance(content_data, dict) else None
		sender_identity = {
			"protocol_version": PROTOCOL_VERSION,
			"client_ref": claim_payload["sender_route"]["client_ref"],
			"public_key_armored": sender_public_key,
			"endpoint_fingerprint": sender_fingerprint,
			"metadata": sender_metadata,
			"identity_signature": "",
		}
		self.state.remember_identity(sender_identity)
		if mark_processed:
			self.state.mark_processed(envelope["message_id"])
		body = content_data.get("body") if content_payload["content_type"] == "message" and isinstance(content_data, dict) else None
		return ReceivedMessage(
			message_id=envelope["message_id"],
			content_id=content_payload["content_id"],
			content_type=content_payload["content_type"],
			content=content_data,
			delivery_role=claim_payload["recipient_role"],
			body=body,
			sender_fingerprint=sender_fingerprint,
			sender_metadata=sender_metadata,
			sender_trust_state=self.trust_state(sender_fingerprint),
			raw_payload=content_payload,
			raw_delivery_claim=claim_payload,
		)

	@staticmethod
	def _validate_visible_recipient_role(content_payload: dict[str, Any], claim_payload: dict[str, Any]) -> None:
		if content_payload.get("content_type") != "message":
			return
		content = content_payload.get("content")
		if not isinstance(content, dict):
			return
		route = claim_payload["recipient_route"]
		visible_field = "visible_bcc" if claim_payload["recipient_role"] == "bcc" else f"visible_{claim_payload['recipient_role']}"
		visible = content.get(visible_field, [])
		matches = any(item == route for item in visible)
		if claim_payload["recipient_role"] == "bcc":
			require(not matches and not any(item == route for item in content.get("visible_to", []) + content.get("visible_cc", [])), "delivery_claim_invalid", "Bcc recipient is visible in signed content")
		else:
			require(matches, "delivery_claim_invalid", "recipient is missing from signed visible recipients")

	def _auth_headers(self) -> dict[str, str]:
		return {"Authorization": f"Bearer {self.auth_token}"}

	def _wss_inbox_uri(self) -> str:
		parsed = urlparse(self.home_server_url)
		host = parsed.netloc
		return f"wss://{host}/v1/client/{self.client_ref}/inbox"

	def _ssl_context(self):
		return wss_ssl_context(self.verify_tls)
