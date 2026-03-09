---
name: market-scan
description: Broad scan of a market segment to identify BD partnership opportunities for Further. Pass a market, trend, or theme to scan.
argument-hint: "<market segment, trend, or theme>"
allowed-tools: Read, Grep, Glob, Bash(curl:*), WebSearch, WebFetch, Write, mcp__perplexity__perplexity_search, mcp__perplexity__perplexity_ask, mcp__perplexity__perplexity_research, mcp__perplexity__perplexity_reason, mcp__firecrawl-mcp__firecrawl_scrape, mcp__firecrawl-mcp__firecrawl_search, mcp__firecrawl-mcp__firecrawl_crawl
---

Perform a broad market scan of the area described in $ARGUMENTS, focused on identifying BD partnership opportunities for Further.

## Research Process

1. **Define scope** — What exactly are we scanning? Set boundaries.
2. **Macro trends** — What's happening at the market level? Growth, regulation, technology shifts.
3. **Company identification** — Find 10-20 companies relevant to this space.
4. **Quick-screen each** — 1-2 sentence summary + partnership relevance score.
5. **Deep-dive top 5** — More detail on the most promising opportunities.
6. **Synthesize** — Themes, timing, and prioritized next steps.

## Output Format

### Market Scan: [Topic]

**Scan Date:** [Today's date]
**Scope:** [1-2 sentences defining what was scanned and boundaries]

**Why This Matters for Further**
- [2-3 bullets on why this market/trend is relevant to our homebuying platform]

**Macro Trends**
1. [Trend] — [Impact on Further's BD strategy]
2. [Trend] — [Impact]
3. [Trend] — [Impact]

**Company Universe**

Quick-screen of all identified companies:

| # | Company | What They Do | Size | Partnership Angle | Fit (1-5) |
|---|---------|-------------|------|-------------------|-----------|
| 1 | | | | | |
| ... | | | | | |

**Top 5 Deep Dives**

For each of the top 5:

#### [Rank]. [Company Name]
- **What they do:** [1-2 sentences]
- **Why they're interesting:** [Specific to Further]
- **Partnership model:** [How a deal might work]
- **Revenue potential:** [Rough estimate or qualitative: high/med/low]
- **Key contact:** [Name + title if findable]
- **Next step:** [Specific action]

**Themes and Insights**
- [3-5 cross-cutting observations from the scan]
- [What surprised you or was counterintuitive]
- [Timing windows or urgency factors]

**Recommended Actions**
| Priority | Action | Owner | Timeline |
|----------|--------|-------|----------|
| 1 | | | |
| 2 | | | |
| 3 | | | |

**Sources**
- All sources with dates

---

After producing the scan, offer to:
1. Save as a markdown file
2. Go deeper on any specific company (/research-company)
3. Evaluate a specific partnership (/research-partnership)
