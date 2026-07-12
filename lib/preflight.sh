#!/usr/bin/env bash
# Preflight checks — verify required tools are available
set -euo pipefail

errors=()

# Check jq
if ! command -v jq &>/dev/null; then
  errors+=("jq is required but not installed. Install via: brew install jq (macOS) or apt-get install jq (Linux)")
fi

# Check git
if ! command -v git &>/dev/null; then
  errors+=("git is required but not installed")
fi

# Check gh CLI
if ! command -v gh &>/dev/null; then
  errors+=("GitHub CLI (gh) is recommended. Install via: brew install gh")
fi

# Check claude CLI
if ! command -v claude &>/dev/null; then
  errors+=("Claude Code CLI is required. Install via: npm install -g @anthropic-ai/claude-code")
fi

# Check Node.js >= 18
if command -v node &>/dev/null; then
  node_version=$(node -v | sed 's/v//' | cut -d. -f1)
  if (( node_version < 18 )); then
    errors+=("Node.js >= 18 required, found v${node_version}")
  fi
else
  errors+=("Node.js is required but not installed")
fi

# Report
if (( ${#errors[@]} > 0 )); then
  echo "Preflight check failed:"
  for e in "${errors[@]}"; do
    echo "  ✗ $e"
  done
  return 1 2>/dev/null || exit 1
fi

echo "  ✓ All preflight checks passed"
return 0 2>/dev/null || exit 0
