from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .errors import EndpointError, require
from .protocol import PROTOCOL_VERSION, canonical_json_bytes, now_iso, validate_content_object
from .transport import normalize_server_url


def load_json(path: Path, default: Any) -> Any:
	if not path.exists():
		return default
	return json.loads(path.read_text(encoding="utf-8"))


def save_json(path: Path, value: Any) -> None:
	path.parent.mkdir(parents=True, exist_ok=True)
	tmp = path.with_suffix(path.suffix + ".tmp")
	tmp.write_bytes(canonical_json_bytes(value))
	os.replace(tmp, path)


class StructuredLog:
	def __init__(self, path: Path):
		self.path = path
		self.path.parent.mkdir(parents=True, exist_ok=True)

	def write(self, event: str, **fields: Any) -> None:
		record = {"time": now_iso(), "event": event, **fields}
		with self.path.open("a", encoding="utf-8") as handle:
			handle.write(canonical_json_bytes(record).decode("utf-8") + "\n")


class ClientState:
	def __init__(self, state_dir: Path):
		self.state_dir = state_dir
		self.state_dir.mkdir(parents=True, exist_ok=True)

	def _path(self, name: str) -> Path:
		return self.state_dir / name

	def get_trust(self, fingerprint: str) -> str:
		trust = load_json(self._path("trust.json"), {})
		return trust.get(fingerprint, "untrusted")

	def mark_trusted(self, fingerprint: str) -> None:
		trust = load_json(self._path("trust.json"), {})
		trust[fingerprint] = "trusted"
		save_json(self._path("trust.json"), trust)

	def remember_identity(self, identity: dict[str, Any]) -> None:
		identities = load_json(self._path("identities.json"), {})
		identities[identity["endpoint_fingerprint"]] = identity
		save_json(self._path("identities.json"), identities)

	def remember_route(self, server_url: str, client_ref: str, fingerprint: str) -> str | None:
		routes = load_json(self._path("routes.json"), {})
		key = _route_key(server_url, client_ref)
		seen = routes.setdefault(key, [])
		warning = None
		if seen and fingerprint not in seen:
			warning = "route_key_changed"
		if fingerprint not in seen:
			seen.append(fingerprint)
		save_json(self._path("routes.json"), routes)
		return warning

	def remember_contact_pin(self, server_url: str, client_ref: str, fingerprint: str) -> None:
		pins = load_json(self._path("contact_pins.json"), {})
		normalized_server_url = normalize_server_url(server_url)
		key = _route_key(normalized_server_url, client_ref)
		pins[key] = {"server_url": normalized_server_url, "client_ref": client_ref, "endpoint_fingerprint": fingerprint}
		save_json(self._path("contact_pins.json"), pins)

	def contact_pin(self, server_url: str, client_ref: str) -> str | None:
		pins = load_json(self._path("contact_pins.json"), {})
		pin = pins.get(_route_key(server_url, client_ref))
		if isinstance(pin, dict) and isinstance(pin.get("endpoint_fingerprint"), str):
			return pin["endpoint_fingerprint"]
		return None

	def has_processed(self, message_id: str) -> bool:
		seen = load_json(self._path("processed_messages.json"), [])
		return message_id in seen

	def mark_processed(self, message_id: str) -> None:
		seen = load_json(self._path("processed_messages.json"), [])
		if message_id not in seen:
			seen.append(message_id)
		save_json(self._path("processed_messages.json"), seen)


class ClientOutbox:
	def __init__(self, state_dir: Path):
		self.path = state_dir / "outbox.json"
		self.path.parent.mkdir(parents=True, exist_ok=True)

	def save(self, content_object: dict[str, Any], envelopes: list[dict[str, Any]]) -> None:
		data = load_json(self.path, {"contents": {}})
		contents = data.setdefault("contents", {})
		entry = contents.setdefault(content_object["content_id"], {"content": content_object, "deliveries": {}})
		entry["content"] = content_object
		deliveries = entry.setdefault("deliveries", {})
		for envelope in envelopes:
			old = deliveries.get(envelope["message_id"])
			if old is None or old.get("status") != "queued":
				deliveries[envelope["message_id"]] = {
					"envelope": envelope,
					"status": "pending",
					"error_code": None,
				}
		save_json(self.path, data)

	def mark(self, message_id: str, status: str, error_code: str | None) -> None:
		data = load_json(self.path, {"contents": {}})
		for entry in data.get("contents", {}).values():
			delivery = entry.get("deliveries", {}).get(message_id)
			if delivery is not None:
				delivery["status"] = status
				delivery["error_code"] = error_code
				break
		self._remove_completed(data)
		save_json(self.path, data)

	def pending_batch(self, limit: int) -> tuple[dict[str, Any], list[dict[str, Any]]] | None:
		data = load_json(self.path, {"contents": {}})
		for entry in data.get("contents", {}).values():
			deliveries = [
				item["envelope"]
				for item in entry.get("deliveries", {}).values()
				if item.get("status") != "queued"
			][:limit]
			if deliveries:
				return entry["content"], deliveries
		return None

	def _remove_completed(self, data: dict[str, Any]) -> None:
		for content_id, entry in list(data.get("contents", {}).items()):
			if entry.get("deliveries") and all(item.get("status") == "queued" for item in entry["deliveries"].values()):
				del data["contents"][content_id]


def _route_key(server_url: str, client_ref: str) -> str:
	require(isinstance(client_ref, str) and client_ref != "", "invalid_envelope", "route.client_ref is required")
	return f"{normalize_server_url(server_url)}|{client_ref}"


@dataclass
class QueueRecord:
	client_ref: str
	message_id: str
	state: str
	envelope: dict[str, Any]
	lease_expires_at: str | None
	delivery_attempts: int
	last_attempt_at: str | None
	reject_reason: str | None = None

	def as_dict(self) -> dict[str, Any]:
		return {
			"client_ref": self.client_ref,
			"message_id": self.message_id,
			"state": self.state,
			"envelope": self.envelope,
			"lease_expires_at": self.lease_expires_at,
			"delivery_attempts": self.delivery_attempts,
			"last_attempt_at": self.last_attempt_at,
			"reject_reason": self.reject_reason,
		}


class MessageQueue:
	def __init__(self, root: Path, rejected_policy: str = "drop"):
		self.root = root
		self.rejected_policy = rejected_policy
		self.root.mkdir(parents=True, exist_ok=True)
		self.db_path = self.root / "endpoint.sqlite3"
		_init_server_database(self.db_path)

	def contains(self, client_ref: str, message_id: str) -> bool:
		with _connection(self.db_path) as conn:
			row = conn.execute(
				"""
				SELECT 1
				FROM queue_messages
				WHERE client_ref = ? AND message_id = ? AND state IN ('queued', 'leased')
				LIMIT 1
				""",
				(client_ref, message_id),
			).fetchone()
		return row is not None

	def add(self, client_ref: str, envelope: dict[str, Any]) -> bool:
		now = now_iso()
		record = QueueRecord(
			client_ref=client_ref,
			message_id=envelope["message_id"],
			state="queued",
			envelope=envelope,
			lease_expires_at=None,
			delivery_attempts=0,
			last_attempt_at=None,
		)
		try:
			with _connection(self.db_path) as conn:
				conn.execute(
					"""
					INSERT INTO queue_messages (
						client_ref,
						message_id,
						state,
						envelope_json,
						lease_expires_at,
						delivery_attempts,
						last_attempt_at,
						reject_reason,
						created_at,
						updated_at
					)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
					""",
					(
						record.client_ref,
						record.message_id,
						record.state,
						canonical_json_bytes(record.envelope).decode("utf-8"),
						record.lease_expires_at,
						record.delivery_attempts,
						record.last_attempt_at,
						record.reject_reason,
						now,
						now,
					),
				)
		except sqlite3.IntegrityError:
			return False
		return True

	def read(self, client_ref: str, message_id: str) -> dict[str, Any] | None:
		with _connection(self.db_path) as conn:
			row = conn.execute(
				"""
				SELECT *
				FROM queue_messages
				WHERE client_ref = ? AND message_id = ? AND state IN ('queued', 'leased')
				""",
				(client_ref, message_id),
			).fetchone()
		if row is None:
			return None
		return _queue_row_as_record(row)

	def read_rejected(self, client_ref: str, message_id: str) -> dict[str, Any] | None:
		with _connection(self.db_path) as conn:
			row = conn.execute(
				"""
				SELECT *
				FROM queue_messages
				WHERE client_ref = ? AND message_id = ? AND state = 'rejected'
				""",
				(client_ref, message_id),
			).fetchone()
		if row is None:
			return None
		return _queue_row_as_record(row)

	def deliverable(self, client_ref: str) -> list[dict[str, Any]]:
		now = now_iso()
		with _connection(self.db_path) as conn:
			conn.execute(
				"""
				UPDATE queue_messages
				SET state = 'queued', lease_expires_at = NULL, updated_at = ?
				WHERE client_ref = ?
					AND state = 'leased'
					AND lease_expires_at IS NOT NULL
					AND lease_expires_at <= ?
				""",
				(now, client_ref, now),
			)
			rows = conn.execute(
				"""
				SELECT *
				FROM queue_messages
				WHERE client_ref = ? AND state = 'queued'
				ORDER BY created_at ASC, message_id ASC
				""",
				(client_ref,),
			).fetchall()
		return [_queue_row_as_record(row) for row in rows]

	def lease(self, client_ref: str, message_id: str, lease_seconds: int) -> dict[str, Any] | None:
		now = now_iso()
		lease_expires_at = (datetime.now(UTC) + timedelta(seconds=lease_seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
		with _connection(self.db_path) as conn:
			result = conn.execute(
				"""
				UPDATE queue_messages
				SET state = 'leased',
					lease_expires_at = ?,
					delivery_attempts = delivery_attempts + 1,
					last_attempt_at = ?,
					updated_at = ?
				WHERE client_ref = ?
					AND message_id = ?
					AND (
						state = 'queued'
						OR (
							state = 'leased'
							AND lease_expires_at IS NOT NULL
							AND lease_expires_at <= ?
						)
					)
				""",
				(lease_expires_at, now, now, client_ref, message_id, now),
			)
			if result.rowcount != 1:
				return None
			row = conn.execute(
				"""
				SELECT *
				FROM queue_messages
				WHERE client_ref = ? AND message_id = ?
				""",
				(client_ref, message_id),
			).fetchone()
		if row is None:
			return None
		return _queue_row_as_record(row)

	def ack(self, client_ref: str, message_id: str) -> bool:
		with _connection(self.db_path) as conn:
			result = conn.execute(
				"""
				DELETE FROM queue_messages
				WHERE client_ref = ? AND message_id = ? AND state IN ('queued', 'leased')
				""",
				(client_ref, message_id),
			)
		return result.rowcount == 1

	def reject(self, client_ref: str, message_id: str, reason: str) -> bool:
		now = now_iso()
		with _connection(self.db_path) as conn:
			if self.rejected_policy == "quarantine":
				result = conn.execute(
					"""
					UPDATE queue_messages
					SET state = 'rejected',
						lease_expires_at = NULL,
						reject_reason = ?,
						updated_at = ?
					WHERE client_ref = ? AND message_id = ? AND state IN ('queued', 'leased')
					""",
					(reason, now, client_ref, message_id),
				)
			else:
				result = conn.execute(
					"""
					DELETE FROM queue_messages
					WHERE client_ref = ? AND message_id = ? AND state IN ('queued', 'leased')
					""",
					(client_ref, message_id),
				)
		return result.rowcount == 1

	def count_active(self, client_ref: str) -> int:
		with _connection(self.db_path) as conn:
			row = conn.execute(
				"""
				SELECT COUNT(*) AS count
				FROM queue_messages
				WHERE client_ref = ? AND state IN ('queued', 'leased')
				""",
				(client_ref,),
			).fetchone()
		return int(row["count"])


class ReplayStore:
	def __init__(self, root: Path):
		self.root = root.parent if root.suffix == ".json" else root
		self.root.mkdir(parents=True, exist_ok=True)
		self.db_path = self.root / "endpoint.sqlite3"
		_init_server_database(self.db_path)

	def seen(self, scope: str, message_id: str) -> bool:
		with _connection(self.db_path) as conn:
			row = conn.execute(
				"""
				SELECT 1
				FROM replay_messages
				WHERE scope = ? AND message_id = ?
				LIMIT 1
				""",
				(scope, message_id),
			).fetchone()
		return row is not None

	def remember(self, scope: str, message_id: str) -> bool:
		with _connection(self.db_path) as conn:
			result = conn.execute(
				"""
				INSERT OR IGNORE INTO replay_messages (scope, message_id, seen_at)
				VALUES (?, ?, ?)
				""",
				(scope, message_id, now_iso()),
			)
		return result.rowcount == 1

	def remember_delivery(self, scope: str, message_id: str, envelope_sha256: str) -> str:
		with _connection(self.db_path) as conn:
			row = conn.execute(
				"SELECT envelope_sha256 FROM replay_messages WHERE scope = ? AND message_id = ?",
				(scope, message_id),
			).fetchone()
			if row is None:
				conn.execute(
					"INSERT INTO replay_messages (scope, message_id, seen_at, envelope_sha256) VALUES (?, ?, ?, ?)",
					(scope, message_id, now_iso(), envelope_sha256),
				)
				return "new"
			if row["envelope_sha256"] == envelope_sha256:
				return "same"
			return "conflict"


def _connect(db_path: Path) -> sqlite3.Connection:
	conn = sqlite3.connect(str(db_path), timeout=30)
	conn.row_factory = sqlite3.Row
	conn.execute("PRAGMA busy_timeout = 5000")
	return conn


@contextmanager
def _connection(db_path: Path) -> Any:
	conn = _connect(db_path)
	try:
		with conn:
			yield conn
	finally:
		conn.close()


def _init_server_database(db_path: Path) -> None:
	db_path.parent.mkdir(parents=True, exist_ok=True)
	with _connection(db_path) as conn:
		conn.execute("PRAGMA journal_mode = WAL")
		conn.execute("PRAGMA synchronous = NORMAL")
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS queue_messages (
				client_ref TEXT NOT NULL,
				message_id TEXT NOT NULL,
				state TEXT NOT NULL CHECK (state IN ('queued', 'leased', 'rejected')),
				envelope_json TEXT NOT NULL,
				lease_expires_at TEXT,
				delivery_attempts INTEGER NOT NULL DEFAULT 0,
				last_attempt_at TEXT,
				reject_reason TEXT,
				created_at TEXT NOT NULL,
				updated_at TEXT NOT NULL,
				PRIMARY KEY (client_ref, message_id)
			)
			"""
		)
		conn.execute(
			"""
			CREATE INDEX IF NOT EXISTS idx_queue_messages_deliverable
			ON queue_messages (client_ref, state, lease_expires_at)
			"""
		)
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS replay_messages (
				scope TEXT NOT NULL,
				message_id TEXT NOT NULL,
				seen_at TEXT NOT NULL,
				envelope_sha256 TEXT,
				PRIMARY KEY (scope, message_id)
			)
			"""
		)
		conn.execute(
			"""
			CREATE TABLE IF NOT EXISTS content_objects (
				content_id TEXT PRIMARY KEY,
				content_sha256 TEXT NOT NULL,
				ciphertext_sha256 TEXT NOT NULL,
				file_path TEXT NOT NULL,
				size_bytes INTEGER NOT NULL,
				created_at TEXT NOT NULL,
				expires_at TEXT,
				updated_at TEXT NOT NULL
			)
			"""
		)
		columns = {row["name"] for row in conn.execute("PRAGMA table_info(replay_messages)").fetchall()}
		if "envelope_sha256" not in columns:
			conn.execute("ALTER TABLE replay_messages ADD COLUMN envelope_sha256 TEXT")


class ContentStore:
	def __init__(self, root: Path):
		self.root = root
		self.root.mkdir(parents=True, exist_ok=True)
		self.content_dir = self.root / "content"
		self.content_dir.mkdir(parents=True, exist_ok=True)
		self.db_path = self.root / "endpoint.sqlite3"
		_init_server_database(self.db_path)

	def put(self, content_object: dict[str, Any]) -> str:
		validate_content_object(content_object)
		require(not _is_expired(content_object.get("expires_at")), "content_expired", "content object has expired", 410)
		content_id = content_object["content_id"]
		path = self._path(content_id)
		with _connection(self.db_path) as conn:
			row = conn.execute(
				"SELECT content_sha256, ciphertext_sha256, file_path FROM content_objects WHERE content_id = ?",
				(content_id,),
			).fetchone()
			if row is not None:
				require(
					row["content_sha256"] == content_object["content_sha256"] and row["ciphertext_sha256"] == content_object["ciphertext_sha256"],
					"content_hash_mismatch",
					"content id is already bound to different content",
					409,
				)
				return "existing"

			tmp = self.content_dir / f".{path.name}.{uuid.uuid4().hex}.tmp"
			tmp.write_text(content_object["ciphertext_armored"], encoding="utf-8")
			try:
				conn.execute(
					"""
					INSERT INTO content_objects (
						content_id, content_sha256, ciphertext_sha256, file_path,
						size_bytes, created_at, expires_at, updated_at
					) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
					""",
					(
						content_id,
						content_object["content_sha256"],
						content_object["ciphertext_sha256"],
						str(path),
						content_object["size_bytes"],
						content_object["created_at"],
						content_object.get("expires_at"),
						now_iso(),
					),
				)
				os.replace(tmp, path)
			except sqlite3.IntegrityError:
				tmp.unlink(missing_ok=True)
				other = conn.execute(
					"SELECT content_sha256, ciphertext_sha256 FROM content_objects WHERE content_id = ?",
					(content_id,),
				).fetchone()
				require(other is not None, "content_unavailable", "content upload was not committed", 503)
				require(
					other["content_sha256"] == content_object["content_sha256"] and other["ciphertext_sha256"] == content_object["ciphertext_sha256"],
					"content_hash_mismatch",
					"content id is already bound to different content",
					409,
				)
				return "existing"
		return "stored"

	def get(self, content_id: str) -> dict[str, Any] | None:
		with _connection(self.db_path) as conn:
			row = conn.execute("SELECT * FROM content_objects WHERE content_id = ?", (content_id,)).fetchone()
		if row is None:
			return None
		if _is_expired(row["expires_at"]):
			self._delete(content_id, row["file_path"])
			return None
		path = Path(row["file_path"])
		if not path.exists():
			return None
		ciphertext = path.read_text(encoding="utf-8")
		content_object = {
			"protocol_version": PROTOCOL_VERSION,
			"content_id": row["content_id"],
			"content_sha256": row["content_sha256"],
			"ciphertext_armored": ciphertext,
			"ciphertext_sha256": row["ciphertext_sha256"],
			"size_bytes": row["size_bytes"],
			"created_at": row["created_at"],
		}
		if row["expires_at"] is not None:
			content_object["expires_at"] = row["expires_at"]
		validate_content_object(content_object)
		return content_object

	def is_expired(self, content_id: str) -> bool:
		with _connection(self.db_path) as conn:
			row = conn.execute("SELECT expires_at FROM content_objects WHERE content_id = ?", (content_id,)).fetchone()
		return row is not None and _is_expired(row["expires_at"])

	def prune_expired(self) -> int:
		with _connection(self.db_path) as conn:
			rows = conn.execute("SELECT content_id, file_path, expires_at FROM content_objects WHERE expires_at IS NOT NULL").fetchall()
		removed = 0
		for row in rows:
			if _is_expired(row["expires_at"]):
				self._delete(row["content_id"], row["file_path"])
				removed += 1
		return removed

	def _path(self, content_id: str) -> Path:
		return self.content_dir / f"{hashlib.sha256(content_id.encode('utf-8')).hexdigest()}.asc"

	def _delete(self, content_id: str, file_path: str) -> None:
		with _connection(self.db_path) as conn:
			conn.execute("DELETE FROM content_objects WHERE content_id = ?", (content_id,))
		try:
			Path(file_path).unlink()
		except FileNotFoundError:
			pass


def _is_expired(value: str | None) -> bool:
	if value is None:
		return False
	try:
		parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
		return parsed <= datetime.now(UTC)
	except ValueError as exc:
		raise EndpointError("invalid_envelope", "content expiration timestamp is invalid", detail=str(exc)) from exc


def _queue_row_as_record(row: sqlite3.Row) -> dict[str, Any]:
	return {
		"client_ref": row["client_ref"],
		"message_id": row["message_id"],
		"state": row["state"],
		"envelope": json.loads(row["envelope_json"]),
		"lease_expires_at": row["lease_expires_at"],
		"delivery_attempts": row["delivery_attempts"],
		"last_attempt_at": row["last_attempt_at"],
		"reject_reason": row["reject_reason"],
	}
