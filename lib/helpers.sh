#!/usr/bin/env bash
# Shared helpers for Claude Code scripts
# Source this file: source "$(dirname "$0")/lib/helpers.sh"

# Cross-platform file permission check (macOS vs Linux)
# Usage: get_file_perms "/path/to/file"
# Returns: numeric permissions (e.g., "600", "755")
get_file_perms() {
  local file="$1"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f%Lp "$file"
  else
    stat -c%a "$file"
  fi
}

# Cross-platform file size in bytes
# Usage: get_file_size "/path/to/file"
get_file_size() {
  local file="$1"
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f%z "$file"
  else
    stat -c%s "$file"
  fi
}

# Resolve Python 3 path (pyenv-aware)
# Usage: PYTHON3=$(resolve_python3)
resolve_python3() {
  if command -v pyenv &>/dev/null; then
    pyenv which python3 2>/dev/null && return
  fi
  which python3 2>/dev/null || which python 2>/dev/null || echo "python3"
}
