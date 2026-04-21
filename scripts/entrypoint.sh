#!/usr/bin/env bash
# entrypoint.sh - Docker entrypoint
#
# Commands:
#   cron      (default) - run supercronic in foreground with the configured schedule
#   once      - run renew-all.sh once and exit
#   host HOST - renew a single host and exit
#   shell     - drop to bash for debugging

set -euo pipefail

ACME_HOME="${ACME_HOME:-/data/acme}"
ACME_EMAIL="${ACME_EMAIL:-}"
CRON_SCHEDULE="${CRON_SCHEDULE:-0 4 * * 1}"  # Mon 04:00 UTC by default
TZ="${TZ:-UTC}"

mkdir -p "${ACME_HOME}" /data/backups /data/logs

# ---- Install acme.sh into /data/acme on first run --------------------------
# This puts all state (account keys, orders) on the persistent volume.
if [[ ! -f "${ACME_HOME}/acme.sh" ]]; then
    if [[ -z "${ACME_EMAIL}" ]]; then
        echo "FATAL: ACME_EMAIL must be set on first run to register with Let's Encrypt" >&2
        exit 1
    fi
    echo "==> First run: installing acme.sh into ${ACME_HOME}"
    # /opt/acme-installer contains an acme.sh source tree copied at image build time
    cd /opt/acme-installer
    ./acme.sh --install \
        --home "${ACME_HOME}" \
        --config-home "${ACME_HOME}/data" \
        --cert-home "${ACME_HOME}/certs" \
        --accountemail "${ACME_EMAIL}" \
        --nocron
    cd /
    # Set the default CA to Let's Encrypt
    "${ACME_HOME}/acme.sh" --home "${ACME_HOME}" --set-default-ca --server letsencrypt
fi

# ---- Load secrets from /run/secrets (Docker secrets) if present ------------
# This lets users mount secrets instead of passing env vars.
load_secret() {
    local name="$1"
    local file="/run/secrets/${name}"
    if [[ -f "${file}" && -z "${!name:-}" ]]; then
        export "${name}=$(cat "${file}")"
    fi
}
load_secret XCC_USER
load_secret XCC_PASS
load_secret CF_Token

# ---- Dispatch --------------------------------------------------------------
cmd="${1:-cron}"
shift || true

case "${cmd}" in
    cron)
        echo "==> Starting supercronic with schedule: ${CRON_SCHEDULE}"
        # Write a crontab file for supercronic; it expects stdin-style format
        CRONFILE="$(mktemp)"
        echo "${CRON_SCHEDULE} /app/renew-all.sh" > "${CRONFILE}"
        exec supercronic -passthrough-logs "${CRONFILE}"
        ;;
    once)
        exec /app/renew-all.sh
        ;;
    host)
        if [[ $# -lt 1 ]]; then
            echo "Usage: host <FQDN> [extra args]" >&2
            exit 1
        fi
        exec python3 /app/xcc-deploy-cert.py --host "$@"
        ;;
    shell)
        exec /bin/bash
        ;;
    *)
        # Anything else: run it directly
        exec "${cmd}" "$@"
        ;;
esac
