"""Production ASGI entrypoint: `python -m portmark.serve_asgi` (the container's CMD).

Section 11 #1: the image used to launch raw uvicorn on 0.0.0.0, bypassing the CLI's loopback-only rule,
with no bearer token, no TLS assertion, and uvicorn's own proxy-header handling. This entrypoint owns
the bind address, so the decision about public exposure is made in one place, before uvicorn starts:

- **Loopback by default.** PORTMARK_BIND_HOST defaults to 127.0.0.1.
- **A public (non-loopback) bind needs ALL of these, checked together** (owner decision D1a):
  1. PORTMARK_PUBLIC_MODE=behind-tls-proxy -- the explicit acknowledgement that a trusted reverse proxy
     terminates TLS in front of this listener;
  2. PORTMARK_A2A_TOKEN -- a bearer token (transport authentication);
  3. PORTMARK_A2A_TRUSTED_PROXIES -- the proxy CIDRs, so client identity survives the proxy hop;
  4. PORTMARK_A2A_PUBLIC_BASE_URL -- the https:// URL clients use.
  The acknowledgement never weakens anything on its own: every missing requirement is reported in one
  refusal, and there is no warning-only path.

Section 11 #6: uvicorn runs with proxy_headers=False. Portmark's trusted-proxy policy
(PORTMARK_A2A_TRUSTED_PROXIES, resolve_client_ip) is then the only code that reads X-Forwarded-For,
always against the raw peer address. Uvicorn's default would rewrite the peer from X-Forwarded-For for
127.0.0.1 before Portmark's policy runs.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from typing import Any

from .a2a import is_loopback_bind, parse_trusted_proxies, validate_public_base_url
from .config import RuntimeConfig
from .logging_config import configure_logging

PUBLIC_MODE_ENV = "PORTMARK_PUBLIC_MODE"
PUBLIC_MODE_ACK = "behind-tls-proxy"
BIND_HOST_ENV = "PORTMARK_BIND_HOST"
BIND_PORT_ENV = "PORTMARK_BIND_PORT"
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8080
REFUSED_EXIT = 2


def public_mode_problems(bind: str, config: RuntimeConfig, acknowledgement: str | None) -> list[str]:
    """Every reason a bind may not start, all at once. Empty means it may start.

    A loopback bind has no public-mode requirements. Any other bind -- a non-loopback address, a
    wildcard (0.0.0.0, ::), or a hostname -- is treated as public and must satisfy all four.
    """
    if is_loopback_bind(bind):
        return []
    problems = []
    ack = (acknowledgement or "").strip()
    if ack != PUBLIC_MODE_ACK:
        shown = f" (got {ack!r})" if ack else ""
        problems.append(
            f"{PUBLIC_MODE_ENV}={PUBLIC_MODE_ACK} is required: acknowledge that a trusted reverse proxy "
            f"terminates TLS in front of this listener{shown}"
        )
    token = config.a2a_token or ""
    if not token.strip():
        problems.append("PORTMARK_A2A_TOKEN is required: a public listener needs bearer-token transport authentication")
    elif token != token.strip() or any(character.isspace() for character in token):
        problems.append("PORTMARK_A2A_TOKEN must not contain whitespace")
    try:
        proxies = parse_trusted_proxies(config.a2a_trusted_proxies)
    except ValueError as error:
        problems.append(f"PORTMARK_A2A_TRUSTED_PROXIES is invalid: {error}")
    else:
        if not proxies:
            problems.append(
                "PORTMARK_A2A_TRUSTED_PROXIES is required: list the reverse proxy's CIDRs, or every client "
                "is identified (and rate-limited) as the proxy"
            )
    public_base_url = config.a2a_public_base_url or ""
    if not public_base_url.strip():
        problems.append("PORTMARK_A2A_PUBLIC_BASE_URL is required: the https:// URL clients reach through the proxy")
    else:
        try:
            validate_public_base_url(public_base_url)
        except ValueError as error:
            problems.append(f"PORTMARK_A2A_PUBLIC_BASE_URL is invalid: {error}")
    return problems


def bind_from_environment(environ: Mapping[str, str]) -> tuple[str, int]:
    host = (environ.get(BIND_HOST_ENV) or DEFAULT_BIND_HOST).strip()
    raw_port = (environ.get(BIND_PORT_ENV) or str(DEFAULT_BIND_PORT)).strip()
    try:
        port = int(raw_port)
    except ValueError as error:
        raise ValueError(f"{BIND_PORT_ENV} must be an integer, got {raw_port!r}") from error
    if not 1 <= port <= 65535:
        raise ValueError(f"{BIND_PORT_ENV} must be between 1 and 65535, got {port}")
    return host, port


def uvicorn_options(host: str, port: int) -> dict[str, Any]:
    return {
        "host": host,
        "port": port,
        # Section 11 #6: Portmark's trusted-proxy policy is the single authority over X-Forwarded-*.
        "proxy_headers": False,
        # Section 11 #2: keep the one redacting root handler; uvicorn installs none of its own.
        "log_config": None,
        "log_level": "warning",
        "access_log": False,
        "limit_concurrency": 32,
        "timeout_keep_alive": 5,
    }


def main(environ: Mapping[str, str] | None = None) -> int:
    environ = os.environ if environ is None else environ
    config = RuntimeConfig.from_environment()
    configure_logging(config.log_level, config.log_json)
    try:
        host, port = bind_from_environment(environ)
    except ValueError as error:
        print(f"portmark: refusing to start: {error}", file=sys.stderr)
        return REFUSED_EXIT
    problems = public_mode_problems(host, config, environ.get(PUBLIC_MODE_ENV))
    if problems:
        print(f"portmark: refusing to bind {host}:{port} publicly. Every requirement below must be met:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return REFUSED_EXIT
    import uvicorn

    uvicorn.run("portmark.asgi:app", **uvicorn_options(host, port))
    return 0


if __name__ == "__main__":
    sys.exit(main())
