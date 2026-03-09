#!/usr/bin/env bash
# File installation and conflict resolution
set -eo pipefail

CLAUDE_DIR="${HOME}/.claude"
INTERACTIVE="${INTERACTIVE:-true}"

install_file() {
  local src="$1" dest="$2" mode="${3:-644}"
  local dest_full="${dest/#\~/$HOME}"

  # Ensure parent directory exists
  mkdir -p "$(dirname "$dest_full")"

  if [[ -f "$dest_full" ]]; then
    # File exists — check if identical
    if diff -q "$src" "$dest_full" &>/dev/null; then
      echo "  o Unchanged: $dest"
      return 0
    fi

    if [[ "$INTERACTIVE" == "true" ]]; then
      echo ""
      echo "  ! Conflict: $dest already exists with different content"
      echo "  [o]verwrite / [s]kip / [d]iff"
      read -rp "  Choice: " choice
      case "$choice" in
        o|O) ;;  # proceed to copy
        d|D)
          diff --color "$dest_full" "$src" || true
          read -rp "  Overwrite? [y/n]: " confirm
          [[ "$confirm" != "y" && "$confirm" != "Y" ]] && return 0
          ;;
        *) echo "  > Skipped: $dest"; return 0 ;;
      esac
    else
      echo "  > Skipped (conflict): $dest"
      return 0
    fi
  fi

  cp "$src" "$dest_full"
  chmod "$mode" "$dest_full"
  echo "  + Installed: $dest"
}

merge_settings() {
  local kit_settings="$1"
  local target="${CLAUDE_DIR}/settings.json"

  if [[ ! -f "$target" ]]; then
    # No existing settings — use kit settings as base
    cp "$kit_settings" "$target"
    echo "  + Created settings.json"
    return 0
  fi

  # Merge using jq
  local jq_script="${SCRIPT_DIR:-$(dirname "$0")}/lib/merge-settings.jq"
  local merged
  merged=$(jq -s -f "$jq_script" "$target" "$kit_settings")

  if [[ -n "$merged" ]]; then
    echo "$merged" | jq '.' > "$target"
    echo "  + Merged settings.json (existing values preserved)"
  else
    echo "  x Failed to merge settings.json"
    return 1
  fi
}
