from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .errors import EndpointError, require


@dataclass
class FederationPolicy:
	public_federation: bool = True
	inbound_whitelist: set[str] = field(default_factory=set)
	outbound_whitelist: set[str] = field(default_factory=set)
	allow_private_networks: bool = False
	allowed_ports: set[int] = field(default_factory=lambda: {443})
	mode: str = "public"


def normalize_server_url(url: str) -> str:
	parsed = urlparse(url)
	require(parsed.scheme == "https", "url_policy_denied", "server URLs must use https")
	require(bool(parsed.hostname), "url_policy_denied", "server URL host is required")
	require(parsed.username is None and parsed.password is None, "url_policy_denied", "URL credentials are not allowed")
	require(parsed.path in {"", "/"}, "url_policy_denied", "server URL paths are not allowed")
	require(parsed.params == "", "url_policy_denied", "URL params are not allowed")
	require(parsed.query == "", "url_policy_denied", "URL query strings are not allowed")
	require(parsed.fragment == "", "url_policy_denied", "URL fragments are not allowed")
	try:
		port = parsed.port
	except ValueError as exc:
		raise EndpointError("url_policy_denied", "server URL port is invalid", detail=str(exc)) from exc
	host = parsed.hostname.lower()
	if ":" in host and not host.startswith("["):
		host = f"[{host}]"
	if port is None:
		return f"https://{host}"
	return f"https://{host}:{port}"


def _host_addresses(hostname: str) -> list[ipaddress._BaseAddress]:
	try:
		infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
	except socket.gaierror as exc:
		raise EndpointError("url_policy_denied", "destination host could not be resolved", detail=str(exc)) from exc
	addresses: list[ipaddress._BaseAddress] = []
	for info in infos:
		addresses.append(ipaddress.ip_address(info[4][0]))
	return addresses


def _private_or_local(address: ipaddress._BaseAddress) -> bool:
	return (
		address.is_private
		or address.is_loopback
		or address.is_link_local
		or address.is_multicast
		or address.is_reserved
		or address.is_unspecified
	)


def validate_https_url(url: str, policy: FederationPolicy, direction: str) -> str:
	normalized = normalize_server_url(url)
	parsed = urlparse(normalized)
	port = parsed.port or 443
	require(port in policy.allowed_ports, "url_policy_denied", "server URL port is not permitted")
	if direction == "outbound" and policy.outbound_whitelist:
		require(normalized in policy.outbound_whitelist, "unknown_destination_server", "server is not in outbound Whitelist")
	if direction == "inbound" and policy.inbound_whitelist:
		require(normalized in policy.inbound_whitelist, "forbidden_peer", "server is not in inbound Whitelist")
	if not policy.allow_private_networks:
		for address in _host_addresses(parsed.hostname or ""):
			require(not _private_or_local(address), "url_policy_denied", "private/local/internal federation addresses are disabled")
	return normalized


def httpx_verify_config(verify_tls: str | bool | ssl.SSLContext) -> bool | ssl.SSLContext:
	if isinstance(verify_tls, str):
		return ssl.create_default_context(cafile=verify_tls)
	return verify_tls


def wss_ssl_context(verify_tls: str | bool | ssl.SSLContext) -> ssl.SSLContext:
	if isinstance(verify_tls, ssl.SSLContext):
		return verify_tls
	if isinstance(verify_tls, str):
		return ssl.create_default_context(cafile=verify_tls)
	if verify_tls is False:
		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE
		return context
	return ssl.create_default_context()
