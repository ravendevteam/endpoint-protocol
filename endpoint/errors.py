from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class EndpointError(Exception):
	code: str
	message: str
	status_code: int = 400
	detail: str | None = None

	def safe_body(self, debug: bool = False) -> dict[str, Any]:
		error: dict[str, Any] = {"code": self.code, "message": self.message}
		if debug and self.detail:
			error["detail"] = self.detail
		return {"protocol_version": "endpoint-poc-1", "error": error}


def require(condition: bool, code: str, message: str, status_code: int = 400, detail: str | None = None) -> None:
	if not condition:
		raise EndpointError(code, message, status_code, detail)
