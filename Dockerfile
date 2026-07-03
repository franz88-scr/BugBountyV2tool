FROM python:3.12-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl wget git jq dnsutils nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/reconchain
COPY reconchain.py reconchain/ pyproject.toml ./

FROM base AS install

RUN pip install --no-cache-dir -e . 2>/dev/null || true

COPY install.sh .
RUN bash install.sh --go-only 2>/dev/null || true

FROM base

COPY --from=install /opt/reconchain /opt/reconchain
COPY --from=install /root/go/bin /usr/local/bin/
COPY --from=install /usr/local/bin /usr/local/bin/

ENV PATH="/opt/reconchain:${PATH}"
WORKDIR /data

ENTRYPOINT ["python3", "/opt/reconchain/reconchain.py"]
CMD ["--help"]
