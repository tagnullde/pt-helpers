#!/usr/bin/env bash
set -euo pipefail

CONF_URL="https://raw.githubusercontent.com/tagnullde/pt-helpers/refs/heads/main/tmux.conf"
CONF_PATH="$HOME/.pt-tmux.conf"
SOCKET="pt"
SESSION="pt"

# Fetch latest config
if ! curl -fsSL "$CONF_URL" -o "$CONF_PATH"; then
    echo "[!] Download failed."
    [[ -f "$CONF_PATH" ]] && echo "[*] Using cached config." || exit 1
fi

# Attach to existing session or create new one
if tmux -L "$SOCKET" has-session -t "$SESSION" 2>/dev/null; then
    tmux -L "$SOCKET" source-file "$CONF_PATH"
    exec tmux -L "$SOCKET" attach -t "$SESSION"
else
    exec tmux -L "$SOCKET" -f "$CONF_PATH" new -s "$SESSION"
fi
