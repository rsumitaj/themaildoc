---
title: "BIMI Definition: brand indicators in email"
description: "BIMI displays your logo beside authenticated mail. Definition, what it requires, and why the certificate is the part that expires."
keyword: "BIMI definition"
term: "BIMI"
definition: "Brand Indicators for Message Identification: a DNS record pointing at a logo and, for most providers, a verified mark certificate, so that participating mailbox providers display the logo beside authenticated mail. Currently an Internet-Draft, not an RFC."
updated: 2026-08-13
seeAlso: ["dmarc", "p-reject"]
tools: ["bimi-checker"]
related: []
---

**Brand Indicators for Message Identification.** The record that puts your logo beside your mail in an inbox.

BIMI is still an Internet-Draft rather than an RFC, which is worth knowing when a tool cites an RFC number for it.

It requires DMARC at `quarantine` or `reject` first. Below enforcement the record is ignored entirely, whatever else is correct.

The record itself is a TXT entry at `default._bimi.<domain>` carrying up to two URLs: `l=` for the logo and `a=` for a Verified Mark Certificate. The logo must be SVG in the Tiny 1.2 Portable/Secure profile, square, and titled. Most providers require the certificate.

The certificate is the part that catches people, because it expires. A BIMI setup that worked last year can be silently dead today, and a checker that only reads the DNS record will still report it as valid.
