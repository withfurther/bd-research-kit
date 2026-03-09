#!/usr/bin/env bash
# Notification hook — native OS notification when Claude needs attention
set -eo pipefail

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
  task_completed)
    title="Claude Code — Research Complete"
    msg="Your research task has finished"
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
  osascript -e "display notification \"$msg\" with title \"$title\" sound name \"Funk\"" 2>/dev/null || true
elif command -v notify-send &>/dev/null; then
  notify-send "$title" "$msg" 2>/dev/null || true
else
  echo "[$title] $msg" >&2
fi
