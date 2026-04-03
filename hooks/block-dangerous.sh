#!/usr/bin/env bash
# Claude Code PreToolUse hook — blocks destructive bash commands
# Pure bash implementation (~5ms vs ~107ms with Python)
# Exit 0 = allow, exit 2 = block
set -euo pipefail

input=$(cat)

# Extract the command field using lightweight jq-style parsing
# Use python only if jq isn't available, but prefer built-in bash
command_str=""
if command -v jq &>/dev/null; then
  command_str=$(echo "$input" | jq -r '.tool_input.command // ""' 2>/dev/null) || true
else
  # Fallback: extract command with grep/sed (handles most cases)
  command_str=$(echo "$input" | grep -o '"command":"[^"]*"' | head -1 | sed 's/"command":"//;s/"$//') || true
fi

if [[ -z "$command_str" ]]; then
  exit 0
fi

# Strip heredoc content — these are string literals, not commands
# Remove <<'EOF'...EOF and <<EOF...EOF blocks
stripped=$(echo "$command_str" | sed '/<<['"'"']\{0,1\}[A-Za-z_]*['"'"']\{0,1\}/,/^[A-Za-z_]*$/d')

# Strip content inside double quotes (commit messages, echo strings, etc.)
# This is a rough heuristic — good enough for pattern matching safety
stripped=$(echo "$stripped" | sed 's/"[^"]*"//g')

# Dangerous patterns — grep -qEi for fast regex matching
# Each pattern is on its own line for maintainability
dangerous_patterns=(
  'rm\s+-rf\s+/([^a-zA-Z]|$)'         # rm -rf / (but not rm -rf /some/path)
  'rm\s+-rf\s+~'                        # rm -rf ~
  'rm\s+-rf\s+\$HOME'                   # rm -rf $HOME
  'rm\s+-rf\s+\.(\s|$|;|&|\|)'         # rm -rf . (current dir)
  'rm\s+-rf\s+\./'                      # rm -rf ./
  'mkfs\.'                              # mkfs.ext4 etc
  'dd\s+if=.*of=/dev/'                  # dd to raw device
  '>\s*/dev/sd'                         # overwrite raw device
  'chmod\s+-R\s+777\s+/'               # chmod -R 777 /
  ':\(\)\{\s*:\|:&\s*\};:'             # fork bomb
  'git\s+push\s+.*--force\s+.*(main|master)'   # force push main/master
  'git\s+push\s+-f\s+.*(main|master)'          # git push -f main/master
  'git\s+push\s+\S+\s+\+(main|master)'         # git push origin +main
  'git\s+reset\s+--hard\s+origin/(main|master)' # hard reset to remote main
  'curl\s+.*\|\s*(sh|bash|zsh)'        # curl | sh (pipe to shell)
  'wget\s+.*\|\s*(sh|bash|zsh)'        # wget | sh
)

# Join patterns with | for a single grep call
joined=$(IFS='|'; echo "${dangerous_patterns[*]}")

if echo "$stripped" | grep -qEi "$joined" 2>/dev/null; then
  cat <<HOOKEOF
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"Blocked by safety hook: destructive command pattern detected"}}
HOOKEOF
  exit 2
fi

exit 0
