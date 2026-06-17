from __future__ import annotations

import pytest


class EndpointTrace:
	def __init__(self, config: pytest.Config, nodeid: str):
		self.enabled = bool(config.getoption("--endpoint-trace"))
		self.nodeid = nodeid
		self._terminal = config.pluginmanager.get_plugin("terminalreporter")
		self._opened = False

	def __call__(self, message: str) -> None:
		if not self.enabled:
			return
		if not self._opened:
			self._write("")
			self._write(f"TRACE {self.nodeid}")
			self._opened = True
		self._write(f"  {message}")

	def _write(self, message: str) -> None:
		if self._terminal is not None:
			self._terminal.write_line(message)
		else:
			print(message)


def pytest_addoption(parser: pytest.Parser) -> None:
	parser.addoption(
		"--endpoint-trace",
		action="store_true",
		default=False,
		help="Print a readable transcript of Endpoint end-to-end protocol steps.",
	)


@pytest.fixture
def trace(request: pytest.FixtureRequest) -> EndpointTrace:
	return EndpointTrace(request.config, request.node.nodeid)
