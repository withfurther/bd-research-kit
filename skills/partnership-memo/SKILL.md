---
name: partnership-memo
description: Generate a formal partnership evaluation memo suitable for sharing with leadership. Pass the company name and partnership type.
argument-hint: "<company name> — <partnership type>"
allowed-tools: Read, Grep, Glob, Bash(curl:*), WebSearch, WebFetch, Write, mcp__perplexity__perplexity_search, mcp__perplexity__perplexity_ask, mcp__perplexity__perplexity_research, mcp__firecrawl-mcp__firecrawl_scrape, mcp__firecrawl-mcp__firecrawl_search, mcp__document-tools__document_convert, mcp__google-workspace__create_doc, mcp__google-workspace__batch_update_doc
---

Generate a formal partnership evaluation memo for the opportunity described in $ARGUMENTS. This memo should be suitable for sharing with Further's leadership team.

## Research Process

1. **Gather context** — Research the company and partnership type (leverage any prior /research-company or /research-partnership output in the conversation)
2. **Structure the memo** — Follow the template below
3. **Write in business voice** — Professional, data-driven, concise
4. **Save as markdown** — Write to a file the user can share or convert

## Memo Template

Write a file named `partnership-memo-[company-slug]-[date].md` with this structure:

```
# Partnership Evaluation Memo

**To:** Further Leadership Team
**From:** BD Team
**Date:** [Today's date]
**Re:** Partnership Opportunity — [Company Name]
**Classification:** Confidential

---

## Executive Summary

[2-3 sentences: what the partnership is, the key value proposition, and the recommendation]

**Recommendation:** [PURSUE / EXPLORE FURTHER / PASS]

---

## Company Overview

[Brief company profile — what they do, scale, funding, relevance to homebuying]

## Partnership Opportunity

### What We're Proposing
[Describe the partnership model in specific terms]

### Value to Further
- [Bullet points — revenue, users, data, brand, etc.]

### Value to [Company]
- [Bullet points — what they get from partnering with us]

## Financial Analysis

| Metric | Estimate | Basis |
|--------|----------|-------|
| Revenue potential (Year 1) | | |
| Revenue potential (Year 2) | | |
| Integration/setup cost | | |
| Ongoing operational cost | | |
| Estimated ROI | | |
| Time to first revenue | | |

## Competitive Context

- [How competitors are positioned relative to this opportunity]
- [Whether this company has competing partnerships]
- [What happens if we DON'T pursue this]

## Risks

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| | | | |

## Resource Requirements

- **Team:** [Who needs to be involved]
- **Timeline:** [Estimated phases and duration]
- **Dependencies:** [What needs to be true for this to work]

## Recommendation and Next Steps

1. [Specific action]
2. [Specific action]
3. [Specific action]

---

*Sources and methodology notes at end of document*
```

After writing the memo file, tell the user where it was saved and offer to create a Google Doc version.
