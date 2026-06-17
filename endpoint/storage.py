from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .protocol import canonical_json_bytes, now_iso


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
		key = f"{server_url}|{client_ref}"
		seen = routes.setdefault(key, [])
		warning = None
		if seen and fingerprint not in seen:
			warning = "route_key_changed"
		if fingerprint not in seen:
			seen.append(fingerprint)
		save_json(self._path("routes.json"), routes)
		return warning

	def has_processed(self, message_id: str) -> bool:
		seen = load_json(self._path("processed_messages.json"), [])
		return message_id in seen

	def mark_processed(self, message_id: str) -> None:
		seen = load_json(self._path("processed_messages.json"), [])
		if message_id not in seen:
			seen.append(message_id)
		save_json(self._path("processed_messages.json"), seen)


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
				PRIMARY KEY (scope, message_id)
			)
			"""
		)


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
