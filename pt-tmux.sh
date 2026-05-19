#!/usr/bin/env bash
set -euo pipefail

CONF_URL="https://raw.githubusercontent.com/tagnullde/pt-helpers/refs/heads/main/tmux.conf"
CONF_PATH="$HOME/.pt-tmux.conf"
SOCKET="pt-x41"
SESSION="x41"

# Fetch latest config (atomic, with timeout)
echo "[*] Fetching config from GitHub..."
tmpfile="$(mktemp "${CONF_PATH}.XXXXXX")"
trap 'rm -f "$tmpfile"' EXIT

if curl --connect-timeout 5 --max-time 15 -fsSL "$CONF_URL" -o "$tmpfile"; then
    mv "$tmpfile" "$CONF_PATH"
    trap - EXIT
    echo "[*] Config updated."
else
    rc=$?
    echo "[!] Download failed (curl exit $rc)."
    if [[ -f "$CONF_PATH" ]]; then
        echo "[*] Using cached config: $CONF_PATH"
    else
        echo "[!] No cached config available. Aborting."
        exit 1
    fi
fi

# Attach to existing session or create new one
if tmux -L "$SOCKET" has-session -t "$SESSION" 2>/dev/null; then
    echo "[*] Attaching to existing session '$SESSION'."
    tmux -L "$SOCKET" source-file "$CONF_PATH"
    exec tmux -L "$SOCKET" attach -d -t "$SESSION"
else
    echo "[*] Starting new session '$SESSION'."
    exec tmux -L "$SOCKET" -f "$CONF_PATH" new -s "$SESSION"
fi
