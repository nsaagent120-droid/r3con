FROM python:3.11-slim

LABEL name="r3con" version="7.3.0" description="r3con v7.3.0 stable offline-first security research toolkit - la vraie version fusionnée"

# Install system dependencies for all domains
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    file \
    binutils-multiarch \
    objdump \
    readelf \
    nm \
    hexdump \
    upx-ucl \
    binwalk \
    exiftool \
    tshark \
    tcpdump \
    nmap \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Optional tools (may not be available in slim, try)
RUN apt-get update && apt-get install -y --no-install-recommends \
    radare2 \
    gdb \
    strace \
    ltrace \
    || echo "Some optional tools not available in slim"

# Create app directory
WORKDIR /app

# Copy requirements and code
COPY requirements.txt pyproject.toml setup.py README.md MANIFEST.in LICENSE CHANGELOG.md INSTALL.md QUICKSTART.md SECURITY_AUDIT.md ./
COPY config.yaml config.pro.yaml ./
COPY cli/ ./cli/
COPY core/ ./core/
COPY modules/ ./modules/
COPY plugins/ ./plugins/
COPY docs/ ./docs/
COPY scripts/ ./scripts/
COPY examples/ ./examples/

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e . && \
    pip install --no-cache-dir \
        capstone \
        lief \
        yara-python \
        jinja2 \
        pyyaml \
        rich \
        click

# Optional heavy deps (best effort)
RUN pip install --no-cache-dir z3-solver tree-sitter tree-sitter-c || echo "z3/tree-sitter optional, skipping"

# Create r3con user
RUN useradd -m -s /bin/bash r3con && \
    mkdir -p /home/r3con/.r3con/cache /home/r3con/.r3con/yara /home/r3con/.r3con/reports /home/r3con/.r3con/workspaces && \
    chown -R r3con:r3con /home/r3con /app

USER r3con
WORKDIR /home/r3con

# Environment
ENV PYTHONPATH=/app
ENV GHIDRA_HOME=/opt/ghidra
ENV R3CON_NO_COLOR=0
ENV R3CON_OFFLINE=0

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python -m cli.main --version || exit 1

# Entry point
ENTRYPOINT ["python", "-m", "cli.main"]
CMD ["--help"]

# Labels for metadata
LABEL org.opencontainers.image.title="r3con" \
      org.opencontainers.image.description="r3con 7.3.0 stable offline-first security toolkit - 49 modules, 35+ tools, 27 CLI groups, supply-chain, diff, sandbox, explicable" \
      org.opencontainers.image.version="7.3.0" \
      org.opencontainers.image.authors="r3con contributors" \
      org.opencontainers.image.source="https://github.com/nsaagent120-droid/r3con" \
      org.opencontainers.image.licenses="MIT"
