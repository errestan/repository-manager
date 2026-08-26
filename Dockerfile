# syntax=docker/dockerfile:1

# --------------------------------------------------------------------- builder
FROM python:3.13-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies resolve in their own layer so source edits do not invalidate them.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev --extra postgres --extra metrics

COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra postgres --extra metrics

# --------------------------------------------------------------------- runtime
FROM python:3.13-slim-bookworm AS runtime

# createrepo-c generates RPM metadata (AD-2); gnupg signs repository metadata
# (AD-6). Neither can be installed by pip, which is why this image exists.
#
# zstd is here for uploads, not for us: dpkg on newer distributions compresses a
# package's control member with zstd, and python-debian reads that by shelling
# out to `unzstd`. Without it those packages are rejected at upload with a
# message about a missing binary, which is a baffling way to learn that an
# image is incomplete.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        createrepo-c \
        gnupg \
        zstd \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# The application owns the repository tree and the GnuPG home; it must not be root
# (specification.md 10.4, 13.2).
RUN groupadd --gid 1000 repoman \
    && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/repoman repoman \
    && mkdir -p /var/lib/repoman /var/lib/repoman/gnupg /srv/repositories \
    && chown -R repoman:repoman /var/lib/repoman /srv/repositories \
    && chmod 700 /var/lib/repoman/gnupg

COPY --from=builder --chown=repoman:repoman /app/.venv /app/.venv
COPY --from=builder --chown=repoman:repoman /app/src /app/src

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    REPOMAN_GNUPGHOME=/var/lib/repoman/gnupg \
    REPOMAN_DATABASE_URL=sqlite+aiosqlite:////var/lib/repoman/repoman.db \
    REPOMAN_ALLOWED_ROOTS=/srv/repositories

WORKDIR /app
USER repoman

VOLUME ["/var/lib/repoman", "/srv/repositories"]
EXPOSE 8000

# TLS is terminated by the reverse proxy in front of this container (AD-13).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; \
sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"

ENTRYPOINT ["repository-manager"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
