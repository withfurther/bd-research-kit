---
name: research-partnership
description: Evaluate a specific partnership opportunity between Further and a target company. Pass the company name and optionally the partnership type.
argument-hint: "<company name> [partnership type]"
allowed-tools: Read, Grep, Glob, Bash(curl:*), WebSearch, WebFetch, mcp__perplexity__perplexity_search, mcp__perplexity__perplexity_ask, mcp__perplexity__perplexity_research, mcp__perplexity__perplexity_reason, mcp__firecrawl-mcp__firecrawl_scrape, mcp__firecrawl-mcp__firecrawl_search
---

Evaluate the partnership opportunity described in $ARGUMENTS between Further and the specified company.

## Research Process

1. **Company context** — Quick profile of the target company (use /research-company output if available)
2. **Partnership landscape** — How do companies like this typically partner? What models exist in the industry?
3. **Competitor partnerships** — Has this company partnered with any of Further's competitors? Who else in our space has similar deals?
4. **Value proposition analysis** — What does each side bring to the table?
5. **Deal structure research** — What are typical commercial terms for this type of partnership?
6. **Risk assessment** — What could go wrong? What are the dependencies?

## Output Format

### Partnership Evaluation: Further x [Company Name]

**Executive Summary**
- 3-4 sentences: what the partnership is, why it matters, and the recommendation (Pursue / Explore / Pass)

**Partnership Model**
- Type: (referral, integration, co-marketing, data sharing, white-label, reseller, etc.)
- How it would work in practice — describe the user experience
- Revenue model: who pays whom, and how

**Value Exchange**

| What Further Gets | What [Company] Gets |
|-------------------|---------------------|
| ... | ... |
| ... | ... |

**Market Context**
- Similar partnerships in the industry (name specific examples)
- Market trends supporting this type of deal
- Competitive dynamics — would competitors react?

**Financial Estimate**
| Metric | Estimate | Assumptions |
|--------|----------|-------------|
| Revenue potential (Year 1) | $ | ... |
| Revenue potential (Year 2) | $ | ... |
| Integration cost | $ or person-months | ... |
| Time to revenue | months | ... |

**Decision Framework**

| Criterion | Score (1-5) | Weight | Weighted |
|-----------|------------|--------|----------|
| Strategic alignment | | 25% | |
| Revenue potential | | 25% | |
| Technical feasibility | | 15% | |
| Competitive moat | | 15% | |
| Brand fit | | 10% | |
| Resource requirements | | 10% | |
| **Total** | | | **/5.0** |

**Risks and Mitigations**
| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| ... | H/M/L | H/M/L | ... |

**Recommended Next Steps**
1. Specific action items with suggested owners
2. Key questions to answer before proceeding
3. Suggested timeline

**Sources**
- All sources with confidence ratings
