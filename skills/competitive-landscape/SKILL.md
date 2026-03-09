---
name: competitive-landscape
description: Map the competitive landscape for a market segment, identifying players, partnerships, and BD opportunities for Further. Pass a market segment or category.
argument-hint: "<market segment or category>"
allowed-tools: Read, Grep, Glob, Bash(curl:*), WebSearch, WebFetch, mcp__perplexity__perplexity_search, mcp__perplexity__perplexity_ask, mcp__perplexity__perplexity_research, mcp__perplexity__perplexity_reason, mcp__firecrawl-mcp__firecrawl_scrape, mcp__firecrawl-mcp__firecrawl_search, mcp__firecrawl-mcp__firecrawl_crawl
---

Map the competitive landscape for the market segment specified in $ARGUMENTS, with a focus on BD partnership opportunities for Further.

## Research Process

1. **Define the segment** — Confirm scope and boundaries of the market being analyzed
2. **Identify major players** — Companies operating in this space (both direct competitors to potential partners, and the partners themselves)
3. **Map existing partnerships** — Who is partnered with whom? What deals have been announced?
4. **Analyze partnership gaps** — Where are companies NOT yet partnered that represents opportunity?
5. **Assess market dynamics** — Trends, consolidation, funding activity, regulatory changes
6. **Prioritize opportunities** — Rank companies by partnership fit with Further

## Output Format

### Competitive Landscape: [Segment Name]

**Market Overview**
- Market size (TAM/SAM/SOM if available)
- Growth rate and key trends
- Regulatory environment
- How this segment relates to the homebuying journey

**Player Map**

Categorize all identified companies:

| Company | Type | Size | Funding | Key Partnerships | Further Fit |
|---------|------|------|---------|-----------------|-------------|
| ... | Leader/Challenger/Niche | Est. revenue or employees | Last round | Notable deals | High/Med/Low |

**Partnership Network**
- Describe the existing web of partnerships in this space
- Identify clusters (e.g., "Lender A partners with Title Co B and Insurance C")
- Note exclusive vs. non-exclusive arrangements where known

**Opportunity Matrix**

| Company | Partnership Type | Revenue Potential | Difficulty | Priority |
|---------|-----------------|-------------------|------------|----------|
| ... | ... | $/High/Med/Low | High/Med/Low | 1-5 |

**Market Trends Affecting BD**
- 3-5 trends that create or close partnership windows
- Timing considerations (seasonal, regulatory deadlines, funding cycles)

**White Space Analysis**
- Partnership models that exist in adjacent markets but not yet in this segment
- Emerging companies to watch (pre-Series A, stealth, recently launched)

**Recommended Targets (Top 5)**
For each:
1. Company name and why
2. Suggested partnership model
3. Estimated effort to close
4. Recommended first contact approach

**Sources**
- All sources with dates and confidence levels
