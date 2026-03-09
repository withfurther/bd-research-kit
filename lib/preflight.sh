#!/usr/bin/env bash
# Preflight checks for BD research kit
set -eo pipefail

error_count=0
errors=""

# Check jq (required for settings merge)
if ! command -v jq &>/dev/null; then
  error_count=$((error_count + 1))
  errors="${errors}jq is required but not installed. Install via: brew install jq (macOS) or apt-get install jq (Linux)\n"
fi

# Check claude CLI
if ! command -v claude &>/dev/null; then
  error_count=$((error_count + 1))
  errors="${errors}Claude Code CLI is required. Install via: npm install -g @anthropic-ai/claude-code\n"
fi

# Check Node.js >= 18
if command -v node &>/dev/null; then
  node_version=$(node -v | sed 's/v//' | cut -d. -f1)
  if (( node_version < 18 )); then
    error_count=$((error_count + 1))
    errors="${errors}Node.js >= 18 required, found v${node_version}\n"
  fi
else
  error_count=$((error_count + 1))
  errors="${errors}Node.js is required but not installed\n"
fi

# Recommended: git
if ! command -v git &>/dev/null; then
  echo "  ! git not found — recommended but not required for research workflows"
fi

# Report errors
if (( error_count > 0 )); then
  echo "  Preflight check failed:"
  echo -e "$errors" | while IFS= read -r line; do
    [[ -n "$line" ]] && echo "  x $line"
  done
  return 1 2>/dev/null || exit 1
fi

echo "  + All preflight checks passed"
return 0 2>/dev/null || exit 0
