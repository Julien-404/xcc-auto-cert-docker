# syntax=docker/dockerfile:1.7
#
# xcc-cert-renewer - Let's Encrypt automation for Lenovo XClarity Controllers.
#
# Image is based on python:3.12-slim (Debian 12). It bundles:
#   - acme.sh (cloned at build, installed into a persistent volume at runtime)
#   - supercronic (lightweight cron replacement, logs to stdout)
#   - the renewer Python script and wrappers
#
# Persistent state goes into /data (mount a volume there).
# Config goes into /config (mount read-only).

# ---------------------------------------------------------------------------
# Stage 1: fetch acme.sh source (pinned version)
# ---------------------------------------------------------------------------
FROM debian:12-slim AS acme-src

ARG ACME_VERSION=3.1.1

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://github.com/acmesh-official/acme.sh/archive/refs/tags/${ACME_VERSION}.tar.gz" \
        -o /tmp/acme.tar.gz \
 && mkdir -p /opt/acme-installer \
 && tar -xzf /tmp/acme.tar.gz -C /opt/acme-installer --strip-components=1 \
 && rm /tmp/acme.tar.gz \
 && chmod +x /opt/acme-installer/acme.sh

# ---------------------------------------------------------------------------
# Stage 2: fetch supercronic binary
# ---------------------------------------------------------------------------
FROM debian:12-slim AS supercronic-src

ARG SUPERCRONIC_VERSION=v0.2.33
ARG TARGETARCH

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

# Supercronic provides separate binaries per arch; map TARGETARCH
RUN case "${TARGETARCH}" in \
        amd64) SC_ARCH=linux-amd64 ;; \
        arm64) SC_ARCH=linux-arm64 ;; \
        arm)   SC_ARCH=linux-arm ;; \
        *) echo "Unsupported arch: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && curl -fsSL \
      "https://github.com/aptible/supercronic/releases/download/${SUPERCRONIC_VERSION}/supercronic-${SC_ARCH}" \
      -o /usr/local/bin/supercronic \
 && chmod +x /usr/local/bin/supercronic

# ---------------------------------------------------------------------------
# Stage 3: final runtime image
# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# System deps:
#   - openssl, curl: required by acme.sh
#   - socat: required by acme.sh for some DNS API integrations
#   - ca-certificates: LE cert validation, Cloudflare API HTTPS
#   - tini: proper PID 1 signal handling
#   - bash: scripts
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        openssl \
        socat \
        tini \
 && rm -rf /var/lib/apt/lists/*

# Python deps - pinned, minimal
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

# Copy acme.sh source (installed at runtime into /data/acme by entrypoint)
COPY --from=acme-src /opt/acme-installer /opt/acme-installer

# Copy supercronic
COPY --from=supercronic-src /usr/local/bin/supercronic /usr/local/bin/supercronic

# Application files
WORKDIR /app
COPY scripts/xcc-deploy-cert.py   /app/xcc-deploy-cert.py
COPY scripts/sg500-deploy-cert.py /app/sg500-deploy-cert.py
COPY scripts/renew-all.sh         /app/renew-all.sh
COPY scripts/entrypoint.sh        /usr/local/bin/entrypoint
RUN chmod +x /app/xcc-deploy-cert.py /app/sg500-deploy-cert.py /app/renew-all.sh /usr/local/bin/entrypoint

# Create non-root user
RUN groupadd --system --gid 1000 acme \
 && useradd --system --uid 1000 --gid acme --home-dir /data --shell /bin/bash acme \
 && mkdir -p /data /config \
 && chown -R acme:acme /data /opt/acme-installer

USER acme

# Volumes for persistent state and read-only config
VOLUME ["/data"]

# Environment defaults
ENV ACME_HOME=/data/acme \
    BACKUP_DIR=/data/backups \
    LOG_DIR=/data/logs \
    HOSTS_FILE=/config/xcc-hosts.conf \
    CRON_SCHEDULE="0 4 * * 1" \
    ACME_SERVER=letsencrypt \
    RENEWAL_THRESHOLD_DAYS=30 \
    TZ=UTC

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/entrypoint"]
CMD ["cron"]
