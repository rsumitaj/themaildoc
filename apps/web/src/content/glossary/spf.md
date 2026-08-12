---
title: "SPF (Sender Policy Framework) Definition"
description: "SPF is a DNS record listing the servers allowed to send mail for a domain. Definition, what it proves, and the ten-lookup limit that breaks records."
keyword: "SPF definition"
term: "SPF"
definition: "Sender Policy Framework: a DNS TXT record listing the servers authorised to send mail using a domain in the SMTP envelope sender. Defined in RFC 7208."
updated: 2026-08-13
seeAlso: ["dkim", "dmarc", "permerror"]
tools: ["spf-checker"]
related: ["what-is-spf"]
---

**Sender Policy Framework.** A published list of the servers allowed to send for a domain.

SPF checks the *envelope sender*, the address given in the SMTP `MAIL FROM` command, which recipients never see. That makes it narrower than most people assume: it does not stop anybody putting your domain in the visible From header. Tying authentication to that header is [DMARC](/glossary/dmarc)'s job.

The mechanism that catches people is the ten DNS lookup limit in RFC 7208 section 4.6.4. Lookups inside your `include`s count against the same ten, so a short record can be over the limit through a vendor's record. Past ten, receivers return [PermError](/glossary/permerror) and SPF fails for every message.
