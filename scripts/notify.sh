#!/usr/bin/env bash
# notify.sh — Telegram notification helper.
#
# Two usage modes:
#   1. Sourced by another script  : provides the `notify_telegram <text>` function.
#   2. Called directly with a msg : `./notify.sh "hello world"` sends that string.
#
# The function is a no-op (returns 0) if TG_BOT_TOKEN or TG_CHAT_ID are unset,
# so callers can always call it without guarding.

notify_telegram() {
    local text="$1"
    if [[ -z "${TG_BOT_TOKEN:-}" || -z "${TG_CHAT_ID:-}" ]]; then
        echo "[notify] TG_BOT_TOKEN or TG_CHAT_ID unset, skipping"
        return 0
    fi
    # Telegram caps text at 4096 chars; truncate conservatively.
    if (( ${#text} > 3900 )); then
        text="${text:0:3800}"$'\n\n[…truncated]'
    fi
    if curl -fsS --max-time 15 -o /dev/null \
            --data-urlencode "chat_id=${TG_CHAT_ID}" \
            --data-urlencode "text=${text}" \
            "https://api.telegram.org/bot${TG_BOT_TOKEN}/sendMessage"; then
        echo "[notify] telegram sent"
        return 0
    else
        # Do NOT echo curl's output — it would leak the bot token via the URL.
        echo "[notify] telegram send failed" >&2
        return 1
    fi
}

# When called as a script rather than sourced, send $1 as the message.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    notify_telegram "${1:-test message from cert-renewer}"
fi
