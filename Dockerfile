FROM python:3.12.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN groupadd --system portmark \
    && useradd --system --gid portmark --home-dir /home/portmark --create-home portmark

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY examples ./examples

RUN python -m pip install --upgrade pip==26.2.1 setuptools==83.0.0 \
    && python -m pip install --no-cache-dir .

USER portmark

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; raise SystemExit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"

CMD ["python", "-m", "uvicorn", "portmark.asgi:app", "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1", "--limit-concurrency", "32", "--timeout-keep-alive", "5", "--log-level", "warning", "--no-access-log"]
