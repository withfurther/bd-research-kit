#!/usr/bin/env bash
# PreToolUse hook — blocks destructive bash commands
# Exit 0 = allow, exit 2 = block
set -eo pipefail

input=$(cat)

command_str=""
if command -v jq &>/dev/null; then
  command_str=$(echo "$input" | jq -r '.tool_input.command // ""' 2>/dev/null) || true
else
  command_str=$(echo "$input" | grep -o '"command":"[^"]*"' | head -1 | sed 's/"command":"//;s/"$//') || true
fi

if [[ -z "$command_str" ]]; then
  exit 0
fi

# Strip heredoc content and quoted strings
stripped=$(echo "$command_str" | sed '/<<['"'"']\{0,1\}[A-Za-z_]*['"'"']\{0,1\}/,/^[A-Za-z_]*$/d')
stripped=$(echo "$stripped" | sed 's/"[^"]*"//g')

# Dangerous patterns
dangerous_patterns=(
  'rm\s+-rf\s+/([^a-zA-Z]|$)'
  'rm\s+-rf\s+~'
  'rm\s+-rf\s+\$HOME'
  'rm\s+-rf\s+\.(\s|$|;|&|\|)'
  'mkfs\.'
  'dd\s+if=.*of=/dev/'
  '>\s*/dev/sd'
  'chmod\s+-R\s+777\s+/'
  'git\s+push\s+.*--force'
  'git\s+push\s+-f'
  'curl\s+.*\|\s*(sh|bash|zsh)'
  'wget\s+.*\|\s*(sh|bash|zsh)'
)

joined=$(IFS='|'; echo "${dangerous_patterns[*]}")

if echo "$stripped" | grep -qEi "$joined" 2>/dev/null; then
  cat <<HOOKEOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Blocked by safety hook: destructive command pattern detected"}}
HOOKEOF
  exit 2
fi

exit 0
