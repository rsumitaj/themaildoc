---
title: "SPF PermError Definition and Causes"
description: "PermError is SPF's permanent failure result. What causes it, why exceeding ten DNS lookups triggers it, and what it does to your mail."
keyword: "SPF PermError"
term: "PermError"
definition: "The SPF result meaning the record could not be evaluated because it is invalid or exceeds a processing limit. It is a failure, not a neutral outcome, and applies to every message the domain sends. Defined in RFC 7208 section 2.6."
updated: 2026-08-13
seeAlso: ["spf", "dmarc"]
tools: ["spf-checker", "spf-flattener"]
related: ["how-to-fix-spf-too-many-dns-lookups", "spf-permerror-explained"]
---

SPF's permanent failure. The record could not be evaluated, so nothing it authorises counts.

The usual cause is the ten DNS lookup limit in RFC 7208 section 4.6.4. Lookups inside your `include`s count against the same total, so a record with four entries can be over the limit through a vendor's own record. Once over, receivers must return PermError.

Other causes: two `v=spf1` records at the same name, more than two lookups returning nothing, a syntax error, or a macro the receiver cannot expand.

The consequence is easy to underestimate. PermError is a failure, not a shrug. Every message the domain sends fails SPF from that moment, and if [DMARC](/glossary/dmarc) alignment depended on SPF, DMARC fails with it.
