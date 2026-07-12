#!/usr/bin/env bash
# Backup existing ~/.claude/ config before modifications
set -euo pipefail

CLAUDE_DIR="${HOME}/.claude"
BACKUP_DIR="${CLAUDE_DIR}/backups/bd-kit-$(date +%Y%m%d-%H%M%S)"

create_backup() {
  if [[ ! -d "$CLAUDE_DIR" ]]; then
    echo "  ℹ No existing ~/.claude/ directory — skip backup"
    return 0
  fi

  mkdir -p "$BACKUP_DIR"

  # Backup settings.json
  [[ -f "$CLAUDE_DIR/settings.json" ]] && cp "$CLAUDE_DIR/settings.json" "$BACKUP_DIR/"

  # Backup existing rules, hooks, skills, agents, output-styles
  for dir in rules hooks skills agents output-styles; do
    if [[ -d "$CLAUDE_DIR/$dir" ]]; then
      cp -r "$CLAUDE_DIR/$dir" "$BACKUP_DIR/"
    fi
  done

  # Backup keybindings
  [[ -f "$CLAUDE_DIR/keybindings.json" ]] && cp "$CLAUDE_DIR/keybindings.json" "$BACKUP_DIR/"

  # Backup statusline and file-suggestion
  [[ -f "$CLAUDE_DIR/statusline-command.sh" ]] && cp "$CLAUDE_DIR/statusline-command.sh" "$BACKUP_DIR/"
  [[ -f "$CLAUDE_DIR/file-suggestion.sh" ]] && cp "$CLAUDE_DIR/file-suggestion.sh" "$BACKUP_DIR/"

  echo "  ✓ Backup created at $BACKUP_DIR"
  echo "$BACKUP_DIR"
}
