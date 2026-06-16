"""MCP JSON-RPC client over HTTP for scanner probes."""

import ipaddress
import json
import socket
from urllib.parse import urlparse

import httpx
import structlog

logger = structlog.get_logger()

SCANNER_USER_AGENT = "Vindicara-MCP-Scanner/0.1.0"


class MCPTransportError(Exception):
    def __init__(self, message: str, status_code: int = 0) -> None:
        self.status_code = status_code
        super().__init__(message)


# Names that must never be probed, even before DNS resolution (defense in depth;
# the resolution check below is the real guard).
_BLOCKED_HOSTNAMES = frozenset({"localhost", "metadata.google.internal", "metadata.goog"})
# Cloud metadata endpoints (also covered by link-local, listed explicitly for clarity).
_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})
# Carrier-grade NAT (RFC 6598) — not flagged by ipaddress.is_private on all versions.
_CGNAT_V4 = ipaddress.ip_network("100.64.0.0/10")

_IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def _ip_is_internal(ip: _IpAddress) -> bool:
    """True for any address an outbound scanner probe must never reach."""
    if str(ip) in _METADATA_IPS:
        return True
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    return ip.version == 4 and ip in _CGNAT_V4


def _resolve_target_ips(hostname: str) -> list[_IpAddress]:
    """Resolve a host to every IP it maps to. IP literals — including octal/hex/
    decimal encodings, which getaddrinfo normalises — are resolved too, closing
    string-based bypasses. Returns [] when the host cannot be resolved (the request
    would simply fail to connect, so there is nothing to SSRF)."""
    try:
        return [ipaddress.ip_address(hostname)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return []
    ips: list[_IpAddress] = []
    for info in infos:
        addr = str(info[4][0]).split("%", 1)[0]
        try:
            ips.append(ipaddress.ip_address(addr))
        except ValueError:
            continue
    return ips


def _validate_url(url: str) -> str:
    """SSRF guard for outbound scanner probes (CWE-918). Parse the URL with a real
    parser and reject any target that resolves to a private, loopback, link-local,
    reserved, carrier-grade-NAT, or cloud-metadata address."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"MCP server URL must use http(s), got {parsed.scheme!r}")
    hostname = (parsed.hostname or "").strip("[]").lower()
    if not hostname:
        raise ValueError("MCP server URL has no host")
    if hostname in _BLOCKED_HOSTNAMES:
        raise ValueError(f"MCP server URL points to a blocked host: {hostname}")
    for ip in _resolve_target_ips(hostname):
        if _ip_is_internal(ip):
            raise ValueError(f"MCP server URL resolves to a blocked internal address: {ip}")
    return url.rstrip("/")


class MCPClient:
    def __init__(
        self,
        server_url: str,
        timeout: float = 10.0,
        auth_header: str = "",
    ) -> None:
        self._server_url = _validate_url(server_url)
        self._timeout = timeout
        self._auth_header = auth_header
        self._request_id = 0

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def _build_headers(self, include_auth: bool = True) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": SCANNER_USER_AGENT,
        }
        if include_auth and self._auth_header:
            headers["Authorization"] = self._auth_header
        return headers

    def _build_request(self, method: str, params: dict[str, object] | None = None) -> dict[str, object]:
        req: dict[str, object] = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
        }
        if params:
            req["params"] = params
        return req

    async def send(
        self,
        method: str,
        params: dict[str, object] | None = None,
        include_auth: bool = True,
    ) -> "MCPResponse":
        payload = self._build_request(method, params)
        headers = self._build_headers(include_auth)
        log = logger.bind(method=method, url=self._server_url)

        # Re-validate at the point of use to mitigate DNS rebinding between
        # construction and request, and never follow redirects into internal space.
        _validate_url(self._server_url)
        try:
            async with httpx.AsyncClient(timeout=self._timeout, follow_redirects=False) as client:
                resp = await client.post(
                    self._server_url,
                    json=payload,
                    headers=headers,
                )
                log.info("mcp.transport.response", status=resp.status_code)
                return MCPResponse(
                    status_code=resp.status_code,
                    body=resp.text,
                    headers=dict(resp.headers),
                )
        except httpx.TimeoutException:
            log.warning("mcp.transport.timeout")
            return MCPResponse(status_code=0, body="", headers={}, timed_out=True)
        except httpx.ConnectError as exc:
            log.warning("mcp.transport.connect_error", error=str(exc))
            return MCPResponse(status_code=0, body=str(exc), headers={}, connection_failed=True)


class MCPResponse:
    def __init__(
        self,
        status_code: int,
        body: str,
        headers: dict[str, str],
        timed_out: bool = False,
        connection_failed: bool = False,
    ) -> None:
        self.status_code = status_code
        self.body = body
        self.headers = headers
        self.timed_out = timed_out
        self.connection_failed = connection_failed

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def json_body(self) -> dict[str, object]:
        try:
            parsed = json.loads(self.body)
            if isinstance(parsed, dict):
                return parsed
            return {}
        except (json.JSONDecodeError, TypeError):
            return {}

    @property
    def has_result(self) -> bool:
        return "result" in self.json_body

    @property
    def has_error(self) -> bool:
        return "error" in self.json_body

    @property
    def result(self) -> dict[str, object] | list[object] | str | int | float | bool | None:
        return self.json_body.get("result")  # type: ignore[return-value]

    @property
    def error_message(self) -> str:
        err = self.json_body.get("error")
        if isinstance(err, dict):
            return str(err.get("message", ""))
        return ""

    @property
    def reveals_internals(self) -> bool:
        body_lower = self.body.lower()
        leak_patterns = [
            "traceback",
            "stack trace",
            "at line",
            'file "/',
            "exception in",
            "/usr/",
            "/home/",
            "/var/",
            "node_modules",
            "site-packages",
        ]
        return any(p in body_lower for p in leak_patterns)
