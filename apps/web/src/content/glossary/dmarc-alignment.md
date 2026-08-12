---
title: "DMARC Alignment Definition and Examples"
description: "Alignment is DMARC requiring SPF or DKIM to pass for the visible From domain, not just any domain. Relaxed and strict modes explained."
keyword: "DMARC alignment"
term: "DMARC alignment"
definition: "The DMARC requirement that the domain authenticated by SPF or DKIM matches the domain in the visible From header, either exactly (strict) or allowing subdomains (relaxed). Defined in RFC 9989 section 4.4."
updated: 2026-08-13
seeAlso: ["dmarc", "spf", "dkim"]
tools: ["dmarc-checker"]
related: ["what-is-dmarc", "dmarc-guide"]
---

The condition most half-configured domains fail without noticing.

DMARC does not ask "did SPF pass". It asks "did SPF pass **for the domain in the From header**". A message can pass SPF for `mailer.vendor.com`, carry a valid DKIM signature from `vendor.com`, and still fail DMARC for `yourcompany.com`, because neither identifier lines up with what the recipient sees. The message authenticated perfectly. It authenticated somebody else.

**Relaxed** alignment, the default, accepts a subdomain: `mail.yourcompany.com` aligns with `yourcompany.com`. **Strict** requires an exact match and breaks most vendor setups without warning.

This is why adding a vendor to your SPF record does not make their mail pass DMARC. The vendor must either use your domain in the envelope sender, or sign with a key published in your DNS.
