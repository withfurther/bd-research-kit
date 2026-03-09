#!/usr/bin/env bash
# bd-research-kit setup — install Claude Code configuration for BD partnership research
# Usage: ./setup.sh [--non-interactive]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDE_DIR="${HOME}/.claude"
KIT_VERSION=$(jq -r '.version' "$SCRIPT_DIR/manifest.json")

# Parse arguments
INTERACTIVE=true
for arg in "$@"; do
  case "$arg" in
    --non-interactive) INTERACTIVE=false ;;
    --help|-h)
      echo "bd-research-kit setup v${KIT_VERSION}"
      echo ""
      echo "Usage: ./setup.sh [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --non-interactive   Skip prompts, install everything with defaults"
      echo "  --help              Show this help"
      exit 0
      ;;
  esac
done

# ============================================================
# Display
# ============================================================
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

header() { echo -e "\n${BOLD}${CYAN}$1${NC}"; }
success() { echo -e "  ${GREEN}+${NC} $1"; }
warn() { echo -e "  ${YELLOW}!${NC} $1"; }
error() { echo -e "  ${RED}x${NC} $1"; }
info() { echo -e "  ${CYAN}i${NC} $1"; }

echo -e "${BOLD}"
echo "=========================================="
echo "  BD Research Kit for Claude Code v${KIT_VERSION}"
echo "=========================================="
echo -e "${NC}"
echo "  This will set up Claude Code with skills,"
echo "  rules, and tools optimized for researching"
echo "  BD partnership opportunities."
echo ""

if [[ "$INTERACTIVE" == "true" ]]; then
  read -rp "  Proceed with installation? [Y/n]: " confirm
  if [[ "$confirm" == "n" || "$confirm" == "N" ]]; then
    echo "  Aborted."
    exit 0
  fi
fi

# ============================================================
# Phase 1: Preflight
# ============================================================
header "Phase 1: Preflight Checks"

source "$SCRIPT_DIR/lib/preflight.sh"

# ============================================================
# Phase 2: Backup
# ============================================================
header "Phase 2: Backup Existing Config"

source "$SCRIPT_DIR/lib/backup.sh"
BACKUP_PATH=$(create_backup)

# ============================================================
# Phase 3: Install Files
# ============================================================
header "Phase 3: Installing Files"

source "$SCRIPT_DIR/lib/merge.sh"

# Ensure directories
mkdir -p "$CLAUDE_DIR"/{rules,hooks,skills,agents,output-styles}

echo ""
echo "  Rules and output styles:"

# Install all files from manifest
manifest_files=$(jq -r '.files[] | "\(.src)|\(.dest)|\(.mode // "644")"' "$SCRIPT_DIR/manifest.json")
while IFS='|' read -r src dest mode; do
  mkdir -p "$(dirname "$CLAUDE_DIR/$dest")"
  install_file "$SCRIPT_DIR/$src" "$CLAUDE_DIR/$dest" "$mode"
done <<< "$manifest_files"

# ============================================================
# Phase 4: Merge Settings
# ============================================================
header "Phase 4: Merging Settings"

# Build combined settings JSON
COMBINED_SETTINGS=$(mktemp)
echo '{}' > "$COMBINED_SETTINGS"

# Add $schema
COMBINED_SETTINGS_CONTENT=$(jq '. + {"$schema": "https://json.schemastore.org/claude-code-settings.json"}' "$COMBINED_SETTINGS")
echo "$COMBINED_SETTINGS_CONTENT" > "$COMBINED_SETTINGS"

# Merge deny rules
deny_rules=$(cat "$SCRIPT_DIR/settings/deny-rules.json")
COMBINED_SETTINGS_CONTENT=$(jq --argjson deny "$deny_rules" '.permissions.deny = $deny' "$COMBINED_SETTINGS")
echo "$COMBINED_SETTINGS_CONTENT" > "$COMBINED_SETTINGS"

# Merge allow rules
allow_rules=$(cat "$SCRIPT_DIR/settings/allow-rules.json")
COMBINED_SETTINGS_CONTENT=$(jq --argjson allow "$allow_rules" '.permissions.allow = $allow' "$COMBINED_SETTINGS")
echo "$COMBINED_SETTINGS_CONTENT" > "$COMBINED_SETTINGS"

# Merge ignore patterns
patterns=$(cat "$SCRIPT_DIR/settings/ignore-patterns.json")
COMBINED_SETTINGS_CONTENT=$(jq --argjson p "$patterns" '.ignorePatterns = $p' "$COMBINED_SETTINGS")
echo "$COMBINED_SETTINGS_CONTENT" > "$COMBINED_SETTINGS"

# Merge preferences
prefs=$(cat "$SCRIPT_DIR/settings/preferences.json")
COMBINED_SETTINGS_CONTENT=$(jq --argjson p "$prefs" '. * $p' "$COMBINED_SETTINGS")
echo "$COMBINED_SETTINGS_CONTENT" > "$COMBINED_SETTINGS"

# Merge hooks
hooks_json=$(jq '.hooks_config' "$SCRIPT_DIR/manifest.json")
COMBINED_SETTINGS_CONTENT=$(jq --argjson h "$hooks_json" '.hooks = $h' "$COMBINED_SETTINGS")
echo "$COMBINED_SETTINGS_CONTENT" > "$COMBINED_SETTINGS"

# Build plugin list
plugin_entries='{}'
for plugin_line in $(jq -r '.plugins.recommended[] | "\(.name)@\(.marketplace)=\(.enabled)"' "$SCRIPT_DIR/manifest.json"); do
  key="${plugin_line%=*}"
  val="${plugin_line#*=}"
  plugin_entries=$(echo "$plugin_entries" | jq --arg k "$key" --argjson v "$val" '. + {($k): $v}')
done
COMBINED_SETTINGS_CONTENT=$(jq --argjson p "$plugin_entries" '.enabledPlugins = $p' "$COMBINED_SETTINGS")
echo "$COMBINED_SETTINGS_CONTENT" > "$COMBINED_SETTINGS"

# Now merge with existing settings.json (or create if new)
merge_settings "$COMBINED_SETTINGS"
rm -f "$COMBINED_SETTINGS"

# ============================================================
# Phase 5: Validate
# ============================================================
header "Phase 5: Validation"

PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); success "$1"; }
fail_check() { FAIL=$((FAIL + 1)); error "$1"; }

# Check core directory exists
[[ -d "$CLAUDE_DIR" ]] && pass "~/.claude/ exists" || fail_check "~/.claude/ missing"

# Check settings.json is valid JSON
if [[ -f "$CLAUDE_DIR/settings.json" ]]; then
  if jq empty "$CLAUDE_DIR/settings.json" 2>/dev/null; then
    pass "settings.json is valid JSON"
  else
    fail_check "settings.json is invalid JSON"
  fi
else
  fail_check "settings.json missing"
fi

# Check rules
for rule in bd-research.md security.md; do
  [[ -f "$CLAUDE_DIR/rules/$rule" ]] && pass "Rule: $rule" || fail_check "Rule missing: $rule"
done

# Check skills
for skill in research-company research-partnership competitive-landscape partnership-memo market-scan; do
  [[ -f "$CLAUDE_DIR/skills/$skill/SKILL.md" ]] && pass "Skill: /$skill" || fail_check "Skill missing: $skill"
done

# Check agent
[[ -f "$CLAUDE_DIR/agents/bd-researcher.md" ]] && pass "Agent: bd-researcher" || fail_check "Agent missing: bd-researcher"

# Check hooks are executable
for hook in notify.sh block-dangerous.sh; do
  if [[ -f "$CLAUDE_DIR/hooks/$hook" && -x "$CLAUDE_DIR/hooks/$hook" ]]; then
    pass "Hook: $hook (executable)"
  else
    fail_check "Hook issue: $hook"
  fi
done

echo ""
echo "  Validation: $PASS passed, $FAIL failed"

# ============================================================
# Phase 6: Write tracking file + Summary
# ============================================================
header "Phase 6: Summary"

# Write tracking file
tracking=$(jq -n \
  --arg v "$KIT_VERSION" \
  --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg repo "$SCRIPT_DIR" \
  '{
    kit: "bd-research-kit",
    version: $v,
    installed_at: $ts,
    repo_path: $repo
  }')
echo "$tracking" > "$CLAUDE_DIR/bd-kit.json"
success "Tracking file written to ~/.claude/bd-kit.json"

echo ""
echo -e "${BOLD}Installation complete!${NC}"
echo ""
echo "  What was installed:"
echo "    - 2 rules (BD research standards, security)"
echo "    - 5 skills: /research-company, /research-partnership,"
echo "      /competitive-landscape, /partnership-memo, /market-scan"
echo "    - 1 agent: bd-researcher (autonomous research)"
echo "    - 1 output style: executive (default)"
echo "    - 2 hooks: notifications, dangerous command blocking"
echo "    - Permission rules for Perplexity, Firecrawl, Google Workspace,"
echo "      and Document Tools MCP servers"
echo ""
echo -e "${BOLD}Getting started:${NC}"
echo ""
echo "  1. Start a new Claude Code session: claude"
echo "  2. Try your first research:"
echo ""
echo "     /research-company Zillow"
echo "     /market-scan mortgage technology startups"
echo "     /competitive-landscape title insurance"
echo ""
echo -e "${BOLD}MCP Server Setup (for full research capabilities):${NC}"
echo ""
echo "  The skills work best with these MCP servers configured. Ask your"
echo "  admin for API keys, then add to ~/.claude.json:"
echo ""
echo "  - Perplexity (web research):  npm install -g @anthropic-ai/mcp-server-perplexity"
echo "  - Firecrawl (website scraping): npm install -g firecrawl-mcp"
echo ""
echo "  Without MCP servers, skills will fall back to WebSearch and WebFetch"
echo "  which still work but provide less comprehensive results."
echo ""
echo -e "${BOLD}Recommended settings:${NC}"
echo ""
echo "  claude config set effortLevel high    # Deeper research and analysis"
echo "  claude config set outputStyle executive # Business-friendly formatting"
echo ""
if [[ -n "${BACKUP_PATH:-}" && "$BACKUP_PATH" != *"skip"* ]]; then
  echo "  Backup of previous config: $BACKUP_PATH"
  echo ""
fi
echo "  To update: cd $(basename "$SCRIPT_DIR") && git pull && ./setup.sh"
echo ""
