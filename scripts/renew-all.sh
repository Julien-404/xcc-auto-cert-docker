#!/usr/bin/env bash
# renew-all.sh - Iterate over all XCC hosts in config/xcc-hosts.conf.
#
# Called by the container's cron (or manually via `docker compose run --rm ...`).
# Exits 0 only if all hosts succeeded or were skipped.

set -euo pipefail

HOSTS_FILE="${HOSTS_FILE:-/config/xcc-hosts.conf}"
LOG_DIR="${LOG_DIR:-/data/logs}"
DEPLOY_SCRIPT="/app/xcc-deploy-cert.py"

mkdir -p "${LOG_DIR}"

if [[ ! -f "${HOSTS_FILE}" ]]; then
    echo "FATAL: hosts file missing: ${HOSTS_FILE}" >&2
    exit 1
fi

failed_hosts=()
ok_count=0

while IFS= read -r raw_host || [[ -n "${raw_host}" ]]; do
    # Strip comments and whitespace
    host="${raw_host%%#*}"
    host="$(echo -n "${host}" | tr -d '[:space:]')"
    [[ -z "${host}" ]] && continue

    log_file="${LOG_DIR}/${host}.log"
    {
        echo "================================================================"
        echo "[$(date -Is)] Processing ${host}"
        echo "================================================================"
    } | tee -a "${log_file}"

    if python3 "${DEPLOY_SCRIPT}" --host "${host}" 2>&1 | tee -a "${log_file}"; then
        ok_count=$((ok_count + 1))
        echo "[$(date -Is)] RESULT ${host}: OK" | tee -a "${log_file}"
    else
        rc=${PIPESTATUS[0]}
        if [[ ${rc} -eq 0 ]]; then
            # Shouldn't happen with tee, but defensive
            ok_count=$((ok_count + 1))
        else
            failed_hosts+=("${host} (rc=${rc})")
            echo "[$(date -Is)] RESULT ${host}: FAIL (rc=${rc})" | tee -a "${log_file}" >&2
        fi
    fi
done < "${HOSTS_FILE}"

echo
echo "=== Summary: OK=${ok_count} FAILED=${#failed_hosts[@]} ==="
if (( ${#failed_hosts[@]} > 0 )); then
    printf '  - %s\n' "${failed_hosts[@]}"
    exit 1
fi
exit 0
