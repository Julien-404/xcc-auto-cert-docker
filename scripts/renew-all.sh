#!/usr/bin/env bash
# renew-all.sh — iterate XCC and SG500 host lists, dispatch to per-type backends.
#
# Called by supercronic cron, or manually via `docker compose run --rm ... once`.
# Exits 0 only if every host succeeded or was skipped.
#
# Optional Telegram alerting: if TG_BOT_TOKEN and TG_CHAT_ID are set, a message
# is sent on failure (and on success if TG_NOTIFY_ALWAYS=1).

set -euo pipefail

XCC_HOSTS_FILE="${HOSTS_FILE:-/config/xcc-hosts.conf}"
SG500_HOSTS_FILE="${SG500_HOSTS_FILE:-/config/sg500-hosts.conf}"
LOG_DIR="${LOG_DIR:-/data/logs}"
XCC_SCRIPT="/app/xcc-deploy-cert.py"
SG500_SCRIPT="/app/sg500-deploy-cert.py"
NOTIFY_SUBJECT="${NOTIFY_SUBJECT:-cert-renewer}"

mkdir -p "${LOG_DIR}"

# Summary sentinel files live under the log dir (persistent volume) so we can
# read them back after both process_file invocations.
# Format per file, one value per line: ok_count, failed_count, then one line
# per failed host ("FQDN (rc=N)").
SUMMARY_DIR="${LOG_DIR}/.summary"
mkdir -p "${SUMMARY_DIR}"

# shellcheck source=./notify.sh
. /app/notify.sh

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
    {
        printf '%d\n%d\n' "${ok}" "${#failed[@]}"
        for f in "${failed[@]}"; do printf '%s\n' "${f}"; done
    } > "${SUMMARY_DIR}/${label}"
}

process_file "${XCC_HOSTS_FILE}"   "xcc"   "${XCC_SCRIPT}"
process_file "${SG500_HOSTS_FILE}" "sg500" "${SG500_SCRIPT}"

total_ok=0
total_failed=0
# Body sections for an eventual Telegram notification.
tg_failed_block=""
tg_ok_block=""
for t in xcc sg500; do
    [[ -f "${SUMMARY_DIR}/${t}" ]] || continue
    mapfile -t lines < "${SUMMARY_DIR}/${t}"
    # Line 0: ok count, line 1: failed count, lines 2+: failed hosts
    ok_t="${lines[0]:-0}"
    failed_t="${lines[1]:-0}"
    total_ok=$((total_ok + ok_t))
    total_failed=$((total_failed + failed_t))
    if (( failed_t > 0 )); then
        tg_failed_block+="${t}:"$'\n'
        for ((i=2; i<${#lines[@]}; i++)); do
            tg_failed_block+="  • ${lines[i]}"$'\n'
        done
    fi
    if (( ok_t > 0 )); then
        tg_ok_block+="${t}: ${ok_t} host(s) OK"$'\n'
    fi
done

run_ts="$(date -Is)"
if (( total_failed > 0 )); then
    echo "=== GLOBAL SUMMARY: ${total_failed} host(s) failed ===" >&2
    notify_telegram "🚨 ${NOTIFY_SUBJECT} FAILED
Run: ${run_ts}
Failed: ${total_failed} / $((total_ok + total_failed))

${tg_failed_block}
${tg_ok_block}
Logs: docker logs xcc-cert-renewer"
    exit 1
fi

echo "=== GLOBAL SUMMARY: all hosts OK ==="
if [[ "${TG_NOTIFY_ALWAYS:-0}" == "1" ]]; then
    notify_telegram "✅ ${NOTIFY_SUBJECT} OK
Run: ${run_ts}
All ${total_ok} host(s) processed successfully.

${tg_ok_block}"
fi
exit 0
