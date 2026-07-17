# ════════════════════════════════════════════════════════════════════
# Stage 1: Builder — compile Go tools, install Python/Ruby deps
# ════════════════════════════════════════════════════════════════════
FROM python:3.12-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    GOPATH=/opt/go \
    PATH="/opt/go/bin:/usr/local/go/bin:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential ca-certificates curl wget git jq unzip \
    ruby ruby-dev libcurl4-openssl-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# ── Go tools — pre-built binaries (no compilation) ─────────────────
RUN mkdir -p /opt/go/bin && \
    ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi && \
    echo "Detected arch: $ARCH" && \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_linux_${ARCH}.zip" -o /tmp/sf.zip && unzip -o /tmp/sf.zip -d /opt/go/bin/ && rm /tmp/sf.zip && \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/latest/download/httpx_linux_${ARCH}.zip" -o /tmp/hx.zip && unzip -o /tmp/hx.zip -d /opt/go/bin/ && rm /tmp/hx.zip && \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_${ARCH}.zip" -o /tmp/nu.zip && unzip -o /tmp/nu.zip -d /opt/go/bin/ && rm /tmp/nu.zip && \
    curl -fsSL "https://github.com/projectdiscovery/naabu/releases/latest/download/naabu_linux_${ARCH}.zip" -o /tmp/na.zip && unzip -o /tmp/na.zip -d /opt/go/bin/ && rm /tmp/na.zip && \
    curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/latest/download/dnsx_linux_${ARCH}.zip" -o /tmp/dx.zip && unzip -o /tmp/dx.zip -d /opt/go/bin/ && rm /tmp/dx.zip && \
    curl -fsSL "https://github.com/projectdiscovery/katana/releases/latest/download/katana_${ARCH}.zip" -o /tmp/kt.zip && unzip -o /tmp/kt.zip -d /opt/go/bin/ && rm /tmp/kt.zip && \
    curl -fsSL "https://github.com/projectdiscovery/alterx/releases/latest/download/alterx_${ARCH}.zip" -o /tmp/al.zip && unzip -o /tmp/al.zip -d /opt/go/bin/ && rm /tmp/al.zip && \
    curl -fsSL "https://github.com/projectdiscovery/cdncheck/releases/latest/download/cdncheck_${ARCH}.zip" -o /tmp/cc.zip && unzip -o /tmp/cc.zip -d /opt/go/bin/ && rm /tmp/cc.zip && \
    curl -fsSL "https://github.com/projectdiscovery/interactsh/releases/latest/download/interactsh-client_${ARCH}.zip" -o /tmp/is.zip && unzip -o /tmp/is.zip -d /opt/go/bin/ && rm /tmp/is.zip && \
    curl -fsSL "https://github.com/hahwul/dalfox/releases/latest/download/dalfox_${ARCH}.tar.gz" -o /tmp/df.tar.gz && tar xzf /tmp/df.tar.gz -C /opt/go/bin/ dalfox && rm /tmp/df.tar.gz && \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/latest/download/ffuf_${ARCH}.tar.gz" -o /tmp/ff.tar.gz && tar xzf /tmp/ff.tar.gz -C /opt/go/bin/ ffuf && rm /tmp/ff.tar.gz && \
    curl -fsSL "https://github.com/zricethezav/gitleaks/releases/latest/download/gitleaks_${ARCH}.tar.gz" -o /tmp/gl.tar.gz && tar xzf /tmp/gl.tar.gz -C /opt/go/bin/ gitleaks && rm /tmp/gl.tar.gz && \
    curl -fsSL "https://github.com/lc/gau/releases/latest/download/gau_${ARCH}.tar.gz" -o /tmp/ga.tar.gz && tar xzf /tmp/ga.tar.gz -C /opt/go/bin/ gau && rm /tmp/ga.tar.gz && \
    curl -fsSL "https://github.com/dwisiswant0/crlfuzz/releases/latest/download/crlfuzz_${ARCH}.tar.gz" -o /tmp/cr.tar.gz && tar xzf /tmp/cr.tar.gz -C /opt/go/bin/ crlfuzz && rm /tmp/cr.tar.gz && \
    curl -fsSL "https://github.com/d3mondev/puredns/releases/latest/download/puredns_${ARCH}.tar.gz" -o /tmp/pd.tar.gz && tar xzf /tmp/pd.tar.gz -C /opt/go/bin/ puredns && rm /tmp/pd.tar.gz && \
    curl -fsSL "https://github.com/tomnomnom/unfurl/releases/latest/download/unfurl_${ARCH}.tar.gz" -o /tmp/uf.tar.gz && tar xzf /tmp/uf.tar.gz -C /opt/go/bin/ unfurl && rm /tmp/uf.tar.gz && \
    curl -fsSL "https://github.com/tomnomnom/qsreplace/releases/latest/download/qsreplace_${ARCH}.tar.gz" -o /tmp/qr.tar.gz && tar xzf /tmp/qr.tar.gz -C /opt/go/bin/ qsreplace && rm /tmp/qr.tar.gz && \
    curl -fsSL "https://github.com/tomnomnom/httprobe/releases/latest/download/httprobe_${ARCH}.tar.gz" -o /tmp/ht.tar.gz && tar xzf /tmp/ht.tar.gz -C /opt/go/bin/ httprobe && rm /tmp/ht.tar.gz && \
    go install github.com/tomnomnom/hacks/kxss@latest && \
    chmod +x /opt/go/bin/* || true

# ── Tools that need go install ─────────────────────────────────────
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; elif [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi && \
    curl -fsSL "https://go.dev/dl/go1.22.5.linux-${ARCH}.tar.gz" | tar -C /usr/local -xz
RUN export GOPATH=/opt/go PATH="/opt/go/bin:/usr/local/go/bin:${PATH}" && \
    go install github.com/owasp-amass/amass/v4/cmd/amass@latest && \
    go install github.com/lc/subjs@latest && \
    go install github.com/jaeles-project/gospider@latest && \
    go install github.com/sensepost/gowitness@latest && \
    go install github.com/BishopFox/cloudfox@latest && \
    git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git /tmp/trufflehog && \
    cd /tmp/trufflehog && go build -o /opt/go/bin/trufflehog ./v3 && rm -rf /tmp/trufflehog

# ── Python tools (install to a prefix we can copy) ─────────────────
RUN pip install --no-cache-dir --break-system-packages --target=/opt/pytools \
    arjun dnsgen wafw00f inql cloud_enum xnLinkFinder clairvoyance corsy

RUN git clone --depth 1 --branch 2.8.13 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap && \
    git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git /opt/SecretFinder && \
    pip install --no-cache-dir --break-system-packages -r /opt/SecretFinder/requirements.txt && \
    git clone --depth 1 https://github.com/commixproject/commix.git /opt/commix

# ── Ruby (wpscan) ──────────────────────────────────────────────────
RUN gem install wpscan --no-document

# ── testssl.sh ─────────────────────────────────────────────────────
RUN git clone --depth 1 --branch 3.2 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh

# ════════════════════════════════════════════════════════════════════
# Stage 2: Runtime — minimal image with only binaries + reconchain
# ════════════════════════════════════════════════════════════════════
FROM python:3.12-slim AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    GOPATH=/opt/go \
    PATH="/opt/reconchain:/opt/go/bin:/usr/local/go/bin:${PATH}"

# ── Runtime-only system packages (no build-essential, no ruby-dev) ─
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget git jq unzip \
    nmap dnsutils whois \
    ruby \
    proxychains-ng \
    libatk1.0-0t64 libatk-bridge2.0-0t64 libcups2t64 libdrm2 libxdamage1 \
    libxkbcommon0 libpango-1.0-0 libcairo2 libasound2t64 libnss3 \
    libxshmfence1 libgbm1 \
    && rm -rf /var/lib/apt/lists/*

# ── Copy Go binaries from builder ──────────────────────────────────
COPY --from=builder /opt/go/bin/ /opt/go/bin/

# ── Copy Go runtime (amass, subjs, gospider, etc. need it) ─────────
COPY --from=builder /usr/local/go/ /usr/local/go/

# ── Copy Python tools from builder ─────────────────────────────────
COPY --from=builder /opt/sqlmap/ /opt/sqlmap/
COPY --from=builder /opt/SecretFinder/ /opt/SecretFinder/
COPY --from=builder /opt/commix/ /opt/commix/
COPY --from=builder /opt/pytools/ /opt/pytools/
COPY --from=builder /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/

# ── Copy Ruby gems (wpscan) from builder ────────────────────────────
COPY --from=builder /usr/lib/ruby/ /usr/lib/ruby/
COPY --from=builder /usr/local/lib/ruby/ /usr/local/lib/ruby/

# ── Copy testssl.sh from builder ───────────────────────────────────
COPY --from=builder /opt/testssl.sh/ /opt/testssl.sh/

# ── Create symlinks for Python tools ───────────────────────────────
RUN ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap && \
    ln -sf /opt/SecretFinder/SecretFinder.py /usr/local/bin/secretfinder && \
    ln -sf /opt/commix/commix.py /usr/local/bin/commix && \
    ln -sf /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh && \
    chmod +x /opt/go/bin/* || true

# ── Reconchain source ─────────────────────────────────────────────
COPY reconchain.py reconchain/ pyproject.toml /opt/reconchain/
RUN pip install --no-cache-dir /opt/reconchain

# ── Non-root user ──────────────────────────────────────────────────
RUN useradd -r -s /bin/false -d /data reconchain && \
    mkdir -p /data && chown reconchain:reconchain /data && \
    chmod 0o700 /data

USER reconchain
WORKDIR /data

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python3 -c "import shutil; assert shutil.which('nuclei'), 'nuclei not found'" && \
        python3 -c "from reconchain.config import __version__; print(f'reconchain {__version__} ok')"

ENTRYPOINT ["python3", "/opt/reconchain/reconchain.py"]
CMD ["--help"]
