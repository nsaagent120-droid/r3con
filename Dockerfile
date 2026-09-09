# r3con v5.0.3 - Professional Docker image
# Multi-stage build for minimal production image

FROM python:3.11-slim-bookworm AS builder

# Security: non-root, minimal deps
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    binutils \
    file \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first for caching
COPY pyproject.toml setup.py README.md LICENSE MANIFEST.in ./
COPY core/__version__.py core/__version__.py
COPY cli/ cli/
COPY core/ core/
COPY layers/ layers/
COPY modules/ modules/
COPY plugins/ plugins/
COPY config.yaml ./

# Build wheel
RUN pip install --upgrade pip build && \
    python -m build --wheel

FROM python:3.11-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="r3con" \
      org.opencontainers.image.description="Offline-first binary, APK, firmware and source security research toolkit" \
      org.opencontainers.image.version="5.0.3" \
      org.opencontainers.image.authors="r3con contributors" \
      org.opencontainers.image.source="https://github.com/nsaagent120-droid/r3con" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    R3CON_NO_COLOR=0 \
    R3CON_NO_ANIMATION=0

WORKDIR /app

# Runtime deps: binutils for fallback disasm, file for magic
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    file \
    binwalk \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 -s /bin/bash r3con

# Copy wheel from builder and install
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --upgrade pip && \
    pip install /tmp/*.whl && \
    pip install "capstone>=5.0.0" "lief>=0.13.0" "pyyaml>=6.0" "jinja2>=3.1.0" || true && \
    rm -rf /tmp/*.whl && \
    rm -rf /root/.cache

# Switch to non-root user
USER r3con
WORKDIR /home/r3con/work

# Default command
ENTRYPOINT ["r3con"]
CMD ["--help"]

# Health check: verify CLI works
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD r3con --help > /dev/null || exit 1
