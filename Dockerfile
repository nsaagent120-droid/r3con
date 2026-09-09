FROM python:3.11-slim

LABEL name="r3con" version="7.1.0" description="r3con v7.1 Titan-Omega-Full-Rival - Unified offline-first security research toolkit"

# Install system dependencies for all domains
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    file \
    strings \
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
    || echo "Some optional tools not available"

# Create app directory
WORKDIR /app

# Copy requirements
COPY requirements.txt pyproject.toml setup.py README.md ./
COPY cli/ ./cli/
COPY core/ ./core/
COPY modules/ ./modules/
COPY config.yaml config.pro.yaml ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -e . && \
    pip install --no-cache-dir \
        capstone \
        pefile \
        yara-python \
        requests \
        markdown \
        lief \
        rich \
        click

# Optional: angr, z3 (heavy)
RUN pip install --no-cache-dir angr z3-solver || echo "angr/z3 optional, skipping"

# Create r3con user
RUN useradd -m -s /bin/bash r3con && \
    mkdir -p /home/r3con/.r3con/cache /home/r3con/.r3con/yara /home/r3con/.r3con/reports && \
    chown -R r3con:r3con /home/r3con /app

USER r3con
WORKDIR /home/r3con

# Environment
ENV PYTHONPATH=/app
ENV GHIDRA_HOME=/opt/ghidra
ENV R3CON_NO_COLOR=0

# Entry point
ENTRYPOINT ["python", "-m", "cli.main"]
CMD ["--help"]

# Labels for metadata
LABEL org.opencontainers.image.title="r3con" \
      org.opencontainers.image.description="Unified offline-first security toolkit - Binary, Malware, Network, Web, Cloud, Container" \
      org.opencontainers.image.version="7.1.0" \
      org.opencontainers.image.authors="r3con contributors" \
      org.opencontainers.image.source="https://github.com/nsaagent120-droid/r3con"
