from __future__ import annotations

import json
from pathlib import Path

import pytest

from endpoint.client_core import EndpointClient, RecipientSpec
from endpoint import cli
from endpoint.errors import EndpointError
from endpoint.storage import ContentStore


def make_client(root: Path, client_ref: str) -> EndpointClient:
	client = EndpointClient(
		client_ref=client_ref,
		home_server_url=f"https://{client_ref}.example.test",
		auth_token=f"{client_ref}-token",
		state_dir=root / "state" / client_ref,
		key_store_dir=root / "keys" / client_ref,
	)
	client.ensure_identity(f"Endpoint {client_ref}", f"{client_ref}@example.test")
	return client


def test_recipients_json_loads_to_cc_and_bcc_specs(tmp_path: Path) -> None:
	bob = make_client(tmp_path, "bob")
	carol = make_client(tmp_path, "carol")
	path = tmp_path / "recipients.json"
	path.write_text(json.dumps({
		"to": [{"server_url": "https://bob.example.test", "identity": bob.export_identity()}],
		"cc": [],
		"bcc": [{"server_url": "https://carol.example.test", "identity": carol.export_identity()}],
	}), encoding="utf-8")
	specs = cli._load_recipient_specs(path)
	assert [(spec.identity["client_ref"], spec.role) for spec in specs] == [("bob", "to"), ("carol", "bcc")]


def test_shared_signed_content_and_private_bcc_claim(tmp_path: Path) -> None:
	alice = make_client(tmp_path, "alice")
	bob = make_client(tmp_path, "bob")
	carol = make_client(tmp_path, "carol")
	identity_bob = bob.export_identity({"username": "bob"})
	identity_carol = carol.export_identity({"username": "carol"})
	to_route = {"server_url": "https://bob.example.test", "client_ref": "bob"}
	signed_content = alice.build_signed_content(
		"message",
		{
			"body": "one signed letter",
			"sender_metadata": {"username": "alice"},
			"visible_to": [to_route],
			"visible_cc": [],
		},
	)
	envelopes = alice.build_delivery_envelopes(
		signed_content,
		[
			RecipientSpec(identity_bob, "https://bob.example.test", "to", "delivery-bob"),
			RecipientSpec(identity_carol, "https://carol.example.test", "bcc", "delivery-carol"),
		],
	)

	assert envelopes[0]["content_id"] == envelopes[1]["content_id"] == signed_content["content_id"]
	assert envelopes[0]["content_sha256"] == envelopes[1]["content_sha256"]
	assert envelopes[0]["ciphertext_armored"] == envelopes[1]["ciphertext_armored"]
	assert envelopes[0]["delivery_ciphertext_armored"] != envelopes[1]["delivery_ciphertext_armored"]

	bob_message = bob.process_envelope(envelopes[0])
	carol_message = carol.process_envelope(envelopes[1])
	assert bob_message.body == carol_message.body == "one signed letter"
	assert bob_message.delivery_role == "to"
	assert carol_message.delivery_role == "bcc"
	assert carol_message.raw_payload["content"]["visible_to"] == [to_route]
	assert "visible_bcc" not in carol_message.raw_payload["content"]


def test_delivery_claim_and_content_bindings_reject_outer_tampering(tmp_path: Path) -> None:
	alice = make_client(tmp_path, "alice")
	bob = make_client(tmp_path, "bob")
	identity_bob = bob.export_identity({"username": "bob"})
	signed_content = alice.build_signed_content(
		"message",
		{"body": "bound content", "sender_metadata": None, "visible_to": [{"server_url": "https://bob.example.test", "client_ref": "bob"}], "visible_cc": []},
	)
	envelope = alice.build_delivery_envelopes(
		signed_content,
		[RecipientSpec(identity_bob, "https://bob.example.test", "to", "delivery")],
	)[0]
	tampered = dict(envelope)
	tampered["recipient_route"] = {"server_url": "https://mallory.example.test", "client_ref": "mallory"}
	with pytest.raises(EndpointError) as route_error:
		bob.process_envelope(tampered)
	assert route_error.value.code == "outer_inner_mismatch"

	content_tampered = dict(envelope)
	content_tampered["content_sha256"] = "0" * 64
	with pytest.raises(EndpointError) as content_error:
		bob.process_envelope(content_tampered)
	assert content_error.value.code == "outer_inner_mismatch"


def test_generic_signed_content_is_delivered_without_message_assumptions(tmp_path: Path) -> None:
	alice = make_client(tmp_path, "alice")
	bob = make_client(tmp_path, "bob")
	identity_bob = bob.export_identity()
	signed_content = alice.build_signed_content("file-manifest", {"name": "report.txt", "size": 42})
	envelope = alice.build_delivery_envelopes(
		signed_content,
		[RecipientSpec(identity_bob, "https://bob.example.test")],
	)[0]
	received = bob.process_envelope(envelope)
	assert received.content_type == "file-manifest"
	assert received.content == {"name": "report.txt", "size": 42}
	assert received.body is None


def test_reference_delivery_fetches_one_durable_content_object(tmp_path: Path) -> None:
	alice = make_client(tmp_path, "alice")
	bob = make_client(tmp_path, "bob")
	carol = make_client(tmp_path, "carol")
	identity_bob = bob.export_identity()
	identity_carol = carol.export_identity()
	signed_content = alice.build_signed_content(
		"message",
		{
			"body": "one stored ciphertext",
			"sender_metadata": None,
			"visible_to": [{"server_url": "https://bob.example.test", "client_ref": "bob"}],
			"visible_cc": [],
		},
	)
	content_ciphertext = alice.openpgp.encrypt_to_many(
		[identity_bob["public_key_armored"], identity_carol["public_key_armored"]],
		json.dumps(signed_content, separators=(",", ":")).encode("utf-8"),
	)
	content_object = alice.build_content_object(signed_content, content_ciphertext)
	envelopes = alice.build_delivery_envelopes(
		signed_content,
		[
			RecipientSpec(identity_bob, "https://bob.example.test", "to", "reference-bob"),
			RecipientSpec(identity_carol, "https://carol.example.test", "bcc", "reference-carol"),
		],
		content_ciphertext=content_ciphertext,
		inline_content=False,
	)
	assert all("content_ref" in envelope and "ciphertext_armored" not in envelope for envelope in envelopes)
	assert envelopes[0]["content_ref"] == envelopes[1]["content_ref"]

	store = ContentStore(tmp_path / "server")
	assert store.put(content_object) == "stored"
	assert store.put(content_object) == "existing"
	fetched = store.get(signed_content["content_id"])
	assert fetched is not None
	assert fetched["ciphertext_armored"] == content_ciphertext
	assert bob.process_envelope(envelopes[0], content_object=fetched).body == "one stored ciphertext"
	assert carol.process_envelope(envelopes[1], content_object=fetched).delivery_role == "bcc"
