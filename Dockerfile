FROM python:3.13-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
ENV PIP_NO_CACHE_DIR=1
ENV PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY src /app/src

RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid appuser --home-dir /app --shell /usr/sbin/nologin --no-create-home appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.getenv(\"PORT\", \"8000\")}/health', timeout=2).read()" || exit 1

CMD ["sh", "-c", "uvicorn src.app:create_runtime_app --factory --host 0.0.0.0 --port ${PORT:-8000}"]
