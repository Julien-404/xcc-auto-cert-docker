#!/usr/bin/env bash
# renew-all.sh — iterate XCC and SG500 host lists, dispatch to per-type backends.
#
# Called by supercronic cron, or manually via `docker compose run --rm ... once`.
# Exits 0 only if every host succeeded or was skipped.

set -euo pipefail

XCC_HOSTS_FILE="${HOSTS_FILE:-/config/xcc-hosts.conf}"
SG500_HOSTS_FILE="${SG500_HOSTS_FILE:-/config/sg500-hosts.conf}"
LOG_DIR="${LOG_DIR:-/data/logs}"
XCC_SCRIPT="/app/xcc-deploy-cert.py"
SG500_SCRIPT="/app/sg500-deploy-cert.py"

mkdir -p "${LOG_DIR}"

# Summary sentinel files live under the log dir (persistent volume) so we can
# read them back after both process_file invocations.
SUMMARY_DIR="${LOG_DIR}/.summary"
mkdir -p "${SUMMARY_DIR}"

process_file() {
    local file="$1"
    local label="$2"
    local script="$3"
    local ok=0
    local failed=()

    if [[ ! -f "${file}" ]]; then
        echo "[${label}] no host file at ${file}, skipping"
        printf '0\n0\n' > "${SUMMARY_DIR}/${label}"
        return 0
    fi

    while IFS= read -r raw || [[ -n "${raw}" ]]; do
        local host="${raw%%#*}"
        host="$(echo -n "${host}" | tr -d '[:space:]')"
        [[ -z "${host}" ]] && continue

        local log_file="${LOG_DIR}/${label}-${host}.log"
        {
            echo "================================================================"
            echo "[$(date -Is)] [${label}] processing ${host}"
            echo "================================================================"
        } | tee -a "${log_file}"

        if python3 "${script}" --host "${host}" 2>&1 | tee -a "${log_file}"; then
            ok=$((ok + 1))
            echo "[$(date -Is)] [${label}] ${host}: OK" | tee -a "${log_file}"
        else
            local rc=${PIPESTATUS[0]}
            failed+=("${host} (rc=${rc})")
            echo "[$(date -Is)] [${label}] ${host}: FAIL rc=${rc}" | tee -a "${log_file}" >&2
        fi
    done < "${file}"

    printf '[%s] SUMMARY ok=%d failed=%d\n' "${label}" "${ok}" "${#failed[@]}"
    for f in "${failed[@]}"; do printf '  - %s\n' "${f}"; done
    printf '%d\n%d\n' "${ok}" "${#failed[@]}" > "${SUMMARY_DIR}/${label}"
}

process_file "${XCC_HOSTS_FILE}"   "xcc"   "${XCC_SCRIPT}"
process_file "${SG500_HOSTS_FILE}" "sg500" "${SG500_SCRIPT}"

total_failed=0
for t in xcc sg500; do
    if [[ -f "${SUMMARY_DIR}/${t}" ]]; then
        # Line 1: ok count, line 2: failed count
        mapfile -t counts < "${SUMMARY_DIR}/${t}"
        total_failed=$((total_failed + counts[1]))
    fi
done

if (( total_failed > 0 )); then
    echo "=== GLOBAL SUMMARY: ${total_failed} host(s) failed ===" >&2
    exit 1
fi
echo "=== GLOBAL SUMMARY: all hosts OK ==="
exit 0
