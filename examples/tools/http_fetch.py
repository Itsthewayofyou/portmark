from __future__ import annotations

import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse

from portmark.security import SecurityError
from portmark.tools import ToolExecutionError, ToolRegistry


MAX_RESPONSE_BYTES = 65_536
TIMEOUT_SECONDS = 2.0
USER_AGENT = "PortmarkExampleHttpFetch/1.0"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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

    request = urllib.request.Request(url, method="GET", headers={"User-Agent": USER_AGENT})
    opener = urllib.request.build_opener(NoRedirectHandler)
    try:
        with opener.open(request, timeout=TIMEOUT_SECONDS) as response:  # nosec B310
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            status = response.status
            content_type = response.headers.get("Content-Type", "")
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise SecurityError("http.fetch redirects are disabled") from error
        raise ToolExecutionError("http.fetch request failed") from error
    except (OSError, TimeoutError) as error:
        raise ToolExecutionError("http.fetch request failed") from error
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
