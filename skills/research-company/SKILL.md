---
name: research-company
description: Deep company profile for BD evaluation. Pass a company name to get a comprehensive overview including leadership, products, financials, partnerships, and strategic fit with Further.
argument-hint: "<company name>"
allowed-tools: Read, Grep, Glob, Bash(curl:*), WebSearch, WebFetch, mcp__perplexity__perplexity_search, mcp__perplexity__perplexity_ask, mcp__perplexity__perplexity_research, mcp__firecrawl-mcp__firecrawl_scrape, mcp__firecrawl-mcp__firecrawl_search
---

Research the company specified in $ARGUMENTS and produce a comprehensive BD profile.

## Research Process

1. **Web search** for the company — get the official website, recent news, funding announcements
2. **Scrape the company website** — understand their products, positioning, and target market
3. **Search for leadership** — CEO, Head of Partnerships/BD, relevant decision-makers
4. **Financial research** — funding rounds, revenue estimates, public filings if applicable
5. **Partnership landscape** — existing partnerships, integrations, channel relationships
6. **News and momentum** — recent announcements, product launches, market moves

## Output Format

### Company Profile: [Company Name]

**Overview**
| Field | Detail |
|-------|--------|
| Founded | Year |
| HQ | City, State |
| Employees | Count or range |
| Funding | Total raised, last round |
| Revenue | Estimate if available |
| Website | URL |

**What They Do**
- Core product/service (2-3 sentences)
- Target market and customer segments
- Business model (SaaS, marketplace, transactional, etc.)

**Leadership**
| Name | Title | Background | LinkedIn |
|------|-------|------------|----------|
| ... | ... | ... | ... |

**Relevant to Further**
- How they intersect with the homebuying journey
- Existing real estate or fintech partnerships
- Integration capabilities (APIs, data feeds, white-label)

**Partnership Fit Assessment**
| Dimension | Rating (1-5) | Notes |
|-----------|-------------|-------|
| Strategic alignment | | |
| Revenue potential | | |
| Technical feasibility | | |
| Competitive moat | | |
| Brand fit | | |
| Resource requirements | | |

**Key Risks**
- List 2-3 risks or concerns

**Recommended Next Steps**
- Specific, actionable items (e.g., "Reach out to [Name], VP Partnerships, via LinkedIn")

**Sources**
- List all sources consulted with confidence notes
