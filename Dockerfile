# Section 11 #4: the base image is pinned by digest (the multi-arch index, observed 2026-09-19), so two
# builds of one commit start from the same bytes. Dependabot's docker ecosystem proposes digest bumps.
FROM python:3.14.6-slim-bookworm@sha256:4c92ffcde4dd6f1ff72a24518f49fd4990b27134987dfa31a733badde66df9f8

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system portmark \
    && useradd --system --gid portmark --home-dir /home/portmark --create-home portmark

# Section 11 #4: dependencies come ONLY from the hash-pinned exports of uv.lock. --require-hashes
# refuses any file whose bytes differ; --no-deps means nothing is resolved at build time.
COPY requirements/bootstrap.txt requirements/runtime.txt ./requirements/
RUN python -m pip install --require-hashes --no-deps -r requirements/bootstrap.txt \
    && python -m pip install --require-hashes --no-deps -r requirements/runtime.txt

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY examples ./examples
# Section 7 PR 3: the hardened-profile probe ships in the image so the deployment recipe is
# executable and testable (deploy/README.md documents the `docker run` hardening flags it verifies).
COPY deploy ./deploy

# Portmark itself, built with the hash-locked setuptools above (no isolated build environment, so no
# unpinned build dependency is fetched).
RUN python -m pip install --no-deps --no-build-isolation . \
    && python -m pip check

USER portmark

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; raise SystemExit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"

# Section 11 #1/#6: the Portmark entrypoint owns the bind. Loopback by default; a public bind needs
# PORTMARK_PUBLIC_MODE=behind-tls-proxy + PORTMARK_A2A_TOKEN + PORTMARK_A2A_TRUSTED_PROXIES +
# an https PORTMARK_A2A_PUBLIC_BASE_URL, all together. uvicorn runs with proxy_headers=False.
ENV PORTMARK_BIND_HOST=127.0.0.1 \
    PORTMARK_BIND_PORT=8080

CMD ["python", "-m", "portmark.serve_asgi"]
