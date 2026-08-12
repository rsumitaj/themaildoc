---
title: "DMARC Definition: what the record does"
description: "DMARC ties SPF and DKIM to the visible From address and tells receivers what to do on failure. Definition, policies, and what it does not cover."
keyword: "DMARC definition"
term: "DMARC"
definition: "Domain-based Message Authentication, Reporting and Conformance: a DNS record that requires SPF or DKIM to pass for the visible From domain, and instructs receivers what to do when neither does. Defined in RFC 9989."
updated: 2026-08-13
seeAlso: ["spf", "dkim", "dmarc-alignment", "p-reject"]
tools: ["dmarc-checker", "spoofability"]
related: ["what-is-dmarc", "dmarc-guide"]
---

**Domain-based Message Authentication, Reporting and Conformance.** The only one of the three records that looks at the From address a recipient actually sees.

DMARC passes when [SPF](/glossary/spf) or [DKIM](/glossary/dkim) passes *and* the domain it passed for aligns with the From domain. Either is sufficient. Both failing triggers the published policy: `none`, `quarantine` or `reject`.

`p=none` is reporting without protection. A domain left there is exactly as spoofable as a domain with no DMARC record.

DMARC governs your exact domain only. It does nothing about a lookalike registration, and nothing about a display name reading as your company with a webmail address behind it.
