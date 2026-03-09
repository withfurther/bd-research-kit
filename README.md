# BD Research Kit for Claude Code

A Claude Code configuration kit optimized for business development partnership research. Installs skills, rules, agents, and permissions that turn Claude Code into a BD research powerhouse.

## What It Does

Sets up Claude Code with everything you need to research potential partners, evaluate partnership opportunities, and produce leadership-ready memos — all from the command line.

### Skills (slash commands)

| Command | What It Does |
|---------|-------------|
| `/research-company Zillow` | Deep company profile: leadership, financials, products, partnership fit |
| `/research-partnership Blend — mortgage API integration` | Full partnership evaluation with financial estimates and decision framework |
| `/competitive-landscape title insurance` | Map all players, partnerships, and white space in a market segment |
| `/partnership-memo Blend — API integration` | Formal memo for leadership with executive summary, financial analysis, risks |
| `/market-scan proptech startups Series A` | Broad scan of 10-20 companies with top-5 deep dives and next steps |

### Also Included

- **BD research rules** — Research methodology, source quality standards, Further context
- **Executive output style** — Business-friendly formatting (bullets, tables, quantified)
- **bd-researcher agent** — Autonomous deep research for multi-step investigations
- **Security rules** — Prevents leaking secrets or sensitive partner info
- **Safety hooks** — Blocks destructive commands, sends native notifications
- **Pre-approved permissions** — Perplexity, Firecrawl, Google Workspace, Document Tools

## Prerequisites

1. **Node.js** >= 18
2. **Claude Code CLI** — `npm install -g @anthropic-ai/claude-code`
3. **jq** — `brew install jq` (macOS) or `apt-get install jq` (Linux)

### Optional (recommended for best results)

These MCP servers give Claude access to web research and document tools. Ask your admin for API keys.

- **Perplexity MCP** — AI-powered web search with citations
- **Firecrawl MCP** — Website scraping and structured data extraction
- **Document Tools MCP** — Read/create PDFs, Word docs, spreadsheets
- **Google Workspace MCP** — Create Google Docs, Sheets, Slides directly

Without MCP servers, the skills fall back to `WebSearch` and `WebFetch` which still work but are less powerful.

## Installation

```bash
git clone <repo-url> bd-research-kit
cd bd-research-kit
./setup.sh
```

The installer will:
1. Check prerequisites (Node.js, Claude CLI, jq)
2. Back up your existing `~/.claude/` config
3. Install rules, skills, agent, hooks, and output style
4. Merge permissions into your `settings.json` (existing settings preserved)
5. Validate the installation

### Non-interactive install

```bash
./setup.sh --non-interactive
```

## Usage

Start a new Claude Code session after installation:

```bash
claude
```

Then use any skill:

```
/research-company Opendoor
```

Claude will use web search, website scraping, and its knowledge to build a comprehensive company profile with partnership fit assessment.

### Workflow Example

A typical BD research workflow:

1. `/market-scan embedded mortgage lending` — Find the landscape
2. `/research-company Blend` — Deep dive on a promising target
3. `/research-partnership Blend — white-label mortgage calculator` — Evaluate the specific deal
4. `/partnership-memo Blend — white-label mortgage calculator` — Write the memo for leadership

### Tips

- **Be specific in your prompts.** `/research-company Blend Labs mortgage` works better than `/research-company Blend`
- **Chain skills together.** Start broad with `/market-scan`, then narrow with `/research-company` on the best targets
- **Ask follow-up questions.** After any skill runs, you can ask Claude to dig deeper on specific aspects
- **Use the agent for complex tasks.** For multi-company comparisons or cross-referencing, Claude will automatically use the bd-researcher agent

## Updating

```bash
cd bd-research-kit
git pull
./setup.sh
```

The installer safely merges — your existing settings and customizations are preserved.

## What Gets Installed

| Location | Files |
|----------|-------|
| `~/.claude/rules/` | `bd-research.md`, `security.md` |
| `~/.claude/skills/` | 5 skill directories |
| `~/.claude/agents/` | `bd-researcher.md` |
| `~/.claude/output-styles/` | `executive.md` |
| `~/.claude/hooks/` | `notify.sh`, `block-dangerous.sh` |
| `~/.claude/settings.json` | Merged permissions, hooks, plugins, preferences |
| `~/.claude/bd-kit.json` | Install tracking (version, timestamp) |

## Uninstalling

To remove the kit's files:

```bash
# Remove kit-specific files
rm ~/.claude/rules/bd-research.md
rm -rf ~/.claude/skills/{research-company,research-partnership,competitive-landscape,partnership-memo,market-scan}
rm ~/.claude/agents/bd-researcher.md
rm ~/.claude/bd-kit.json

# Or restore from backup
cp ~/.claude/backups/bd-kit-*/settings.json ~/.claude/settings.json
```
