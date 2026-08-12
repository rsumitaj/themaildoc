---
title: "DANE Definition: TLSA records for mail"
description: "DANE pins a mail server's certificate in DNSSEC-signed DNS. Definition, how it differs from MTA-STS, and why it needs DNSSEC."
keyword: "DANE definition"
term: "DANE"
definition: "DNS-Based Authentication of Named Entities: a TLSA record in DNSSEC-signed DNS that states which certificate a mail server must present, removing reliance on public certificate authorities. Defined in RFC 6698 and RFC 7672 for SMTP."
updated: 2026-08-13
seeAlso: ["dnssec", "mta-sts", "tls-rpt"]
tools: ["dnssec-checker"]
related: []
---

**DNS-Based Authentication of Named Entities.** The other way to require TLS for inbound mail.

DANE publishes a TLSA record stating which certificate, or which issuing key, your mail server will present. A sending server that supports DANE checks the presented certificate against it and refuses to deliver on a mismatch.

It requires [DNSSEC](/glossary/dnssec). Without signed DNS an attacker could simply forge the TLSA record, so the whole mechanism rests on the chain of trust being intact.

Compared with [MTA-STS](/glossary/mta-sts): DANE is stronger, because it does not trust the public certificate authority system, and harder to deploy, because it needs DNSSEC and careful certificate rotation. MTA-STS needs no DNSSEC and is trivial to publish. Large providers differ on which they support, and publishing both is a legitimate position.
