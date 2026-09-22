from __future__ import annotations

import http.client
import ssl
from typing import Any
from urllib.parse import urlparse

from portmark.providers import PinnedHTTPSConnection, resolve_public_address
from portmark.security import SecurityError
from portmark.tools import ToolExecutionError, ToolRegistry


MAX_RESPONSE_BYTES = 65_536
TIMEOUT_SECONDS = 2.0
USER_AGENT = "PortmarkExampleHttpFetch/1.0"


def registry() -> ToolRegistry:
    tools = ToolRegistry(default_timeout=TIMEOUT_SECONDS + 0.5, max_output_bytes=MAX_RESPONSE_BYTES + 4096)
    tools.register("http.fetch", fetch, timeout=TIMEOUT_SECONDS + 0.5)
    return tools


def fetch(arguments: dict[str, Any]) -> dict[str, Any]:
    url = _required_string(arguments, "url")
    method = arguments.get("method", "GET")
    if method != "GET":
        raise SecurityError("http.fetch only supports GET")
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        raise SecurityError("http.fetch requires https URLs")
    if not parsed.hostname:
        raise SecurityError("http.fetch requires an absolute URL")
    if parsed.username is not None or parsed.password is not None:
        raise SecurityError("http.fetch URLs must not contain userinfo")
    hostname = parsed.hostname
    try:
        port = parsed.port or 443
    except ValueError as error:
        raise SecurityError("http.fetch URL has an invalid port") from error
    target = (parsed.path or "/") + (f"?{parsed.query}" if parsed.query else "")

    # The host policy allowlists the NAME; the name must also resolve only to public addresses, and the
    # connection goes to the address checked here -- DNS is not asked again, so the name cannot be
    # re-pointed (rebound) at an internal address between the check and the connect. TLS still verifies
    # the certificate against the original name.
    try:
        address = resolve_public_address(hostname, port)
    except OSError as error:
        raise ToolExecutionError("http.fetch request failed") from error
    host_header = f"[{hostname}]" if ":" in hostname else hostname
    if port != 443:
        host_header += f":{port}"
    connection = PinnedHTTPSConnection(address, port, hostname, TIMEOUT_SECONDS, ssl.create_default_context())
    try:
        connection.request("GET", target, headers={"Host": host_header, "User-Agent": USER_AGENT})
        response = connection.getresponse()
        status = response.status
        if 300 <= status < 400:
            raise SecurityError("http.fetch redirects are disabled")
        if status >= 400:
            raise ToolExecutionError("http.fetch request failed")
        raw = response.read(MAX_RESPONSE_BYTES + 1)
        content_type = response.getheader("Content-Type", "") or ""
    except (OSError, http.client.HTTPException) as error:
        raise ToolExecutionError("http.fetch request failed") from error
    finally:
        connection.close()
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ToolExecutionError("http.fetch response exceeds output limit")
    return {
        "url": url,
        "status": status,
        "content_type": content_type,
        "body": raw.decode("utf-8", errors="replace"),
    }


def _required_string(arguments: dict[str, Any], name: str) -> str:
    value = arguments.get(name)
    if not isinstance(value, str) or not value:
        raise SecurityError(f"http.fetch requires non-empty {name}")
    return value
