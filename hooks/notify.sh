#!/usr/bin/env bash
# Claude Code notification hook — cross-platform native notification
# Fires on Notification events (permission prompts, idle, auth)
# Input: JSON on stdin with notification details
set -euo pipefail

input=$(cat)
type=$(echo "$input" | jq -r '.type // "unknown"')

case "$type" in
  permission_prompt)
    title="Claude Code — Permission Required"
    msg="Claude is waiting for your approval"
    ;;
  idle_prompt)
    title="Claude Code — Waiting"
    msg="Claude is waiting for input"
    ;;
  auth_success)
    title="Claude Code — Authenticated"
    msg="Authentication completed successfully"
    ;;
  task_completed)
    title="Claude Code — Task Complete"
    msg="A background task has finished"
    ;;
  stop)
    title="Claude Code — Done"
    msg="Claude has finished responding"
    ;;
  *)
    title="Claude Code"
    msg="Needs your attention"
    ;;
esac

# Cross-platform notification
if [[ "$OSTYPE" == "darwin"* ]]; then
  # macOS — use osascript
  osascript -e "display notification \"$msg\" with title \"$title\" sound name \"Funk\"" 2>/dev/null || true
elif command -v notify-send &>/dev/null; then
  # Linux with libnotify (GNOME, KDE, etc.)
  notify-send "$title" "$msg" 2>/dev/null || true
else
  # Fallback — print to stderr so the user sees it
  echo "[$title] $msg" >&2
fi
