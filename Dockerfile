# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# snitch - Telegram moderator bot
#
# Two stages: wheels are built once with the compiler toolchain available, then
# copied into a slim runtime that has no build tools at all. The final image
# contains no source and runs as a non-root user.
# ---------------------------------------------------------------------------

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_DOWNLOADS=never

COPY --from=ghcr.io/astral-sh/uv:0.12 /uv /usr/local/bin/uv

WORKDIR /src

# Dependencies are their own layer, so editing source does not re-resolve them.
# The lock file makes the build reproducible; --locked fails loudly if
# pyproject.toml and uv.lock ever drift apart.
#
# --no-editable is essential: a default `uv sync` installs the project as an
# editable .pth pointing at /src/src, which does not exist in the runtime image.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-install-project

COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked --no-dev --no-editable


# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    DATA_DIR=/app/data

# A fixed uid/gid keeps bind-mounted volume permissions predictable.
RUN groupadd --gid 10001 snitch \
    && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin snitch \
    && mkdir -p /app/data \
    && chown -R 10001:10001 /app

COPY --from=builder --chown=10001:10001 /opt/venv /opt/venv

WORKDIR /app

USER 10001:10001
VOLUME ["/app/data"]

# Long polling: the bot makes outbound requests only, so no port is published.
# There is nothing to probe, so the container's liveness is "the process runs".
CMD ["python", "-m", "snitch"]
