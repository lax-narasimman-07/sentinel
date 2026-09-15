FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl wget git build-essential nmap python3-dev \
    && rm -rf /var/lib/apt/lists/*

RUN curl -sSL https://raw.githubusercontent.com/projectdiscovery/nuclei/main/scripts/install.sh | bash -s -- -v 3.3.9 /usr/local/bin/nuclei || true
RUN curl -sSL https://raw.githubusercontent.com/projectdiscovery/subfinder/v2/cmd/subfinder/install.sh | bash -s -- -v 2.6.7 /usr/local/bin/subfinder || true
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true
RUN go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest 2>/dev/null || true
RUN go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
RUN go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest 2>/dev/null || true
RUN curl -sSL https://github.com/ffuf/ffuf/releases/download/v2.1.0/ffuf_2.1.0_linux_amd64.tar.gz | tar xz -C /usr/local/bin ffuf || true

FROM base AS app

WORKDIR /app

RUN useradd -m -s /bin/bash omega

COPY --chown=omega:omega pyproject.toml README.md ./
COPY --chown=omega:omega omega/ ./omega/

RUN pip install --no-cache-dir -e ".[browser]" || pip install --no-cache-dir -e .

USER omega

EXPOSE 8000 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/system || exit 1

CMD ["python", "-m", "omega.cli", "start", "--all"]
