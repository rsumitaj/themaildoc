---
title: "DNSSEC Definition: signed DNS explained"
description: "DNSSEC signs DNS answers so a resolver can tell real records from forged ones. Definition, the DS record, and what a broken chain does."
keyword: "DNSSEC definition"
term: "DNSSEC"
definition: "Domain Name System Security Extensions: cryptographic signatures on DNS records that let a validating resolver confirm an answer came from the real zone and was not altered. Defined in RFC 4033 through RFC 4035."
updated: 2026-08-13
seeAlso: ["dane", "mta-sts"]
tools: ["dnssec-checker"]
related: []
---

**Domain Name System Security Extensions.** Signatures on DNS answers, so a resolver can tell your records from forged ones.

It matters for mail because every record that protects your email lives in DNS. An attacker who can poison a resolver's cache can replace your MX, your SPF and your DMARC record without touching your account. DNSSEC is what makes that detectable.

Signing the zone is only half of it. The registrar must publish a matching DS record at the parent, or the chain of trust is broken at the top and validating resolvers treat the zone as unsigned. That is the cost of DNSSEC with none of the benefit, and it is a common state after a key rotation done on one side only.

A zone whose signatures fail to validate is worse than an unsigned one: validating resolvers, which includes Google and Cloudflare, refuse the answers entirely and the domain stops resolving for a large part of the internet.
