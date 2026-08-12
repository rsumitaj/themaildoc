---
title: "TLS-RPT Definition: SMTP TLS reporting"
description: "TLS-RPT asks sending servers to report failed TLS connections to your mail servers. Definition, what it reports, and why it pairs with MTA-STS."
keyword: "TLS-RPT definition"
term: "TLS-RPT"
definition: "SMTP TLS Reporting: a DNS record asking sending servers to send daily reports about failures to establish a secure connection to a domain's mail servers. Defined in RFC 8460."
updated: 2026-08-13
seeAlso: ["mta-sts", "dane"]
tools: ["tls-rpt-checker", "tls-rpt-generator"]
related: []
---

**SMTP TLS Reporting.** The visibility half of transport security.

A TXT record at `_smtp._tls.<domain>` names an address for daily reports. Sending servers use it to tell you when they could not establish a secure connection to your mail servers, including why: an expired certificate, a name that did not match, a failed STARTTLS negotiation, or an [MTA-STS](/glossary/mta-sts) policy they could not satisfy.

It changes nothing about how mail is handled. Its entire value is that TLS failures are otherwise completely invisible to the receiving domain: the sender either falls back to plaintext or gives up, and nobody tells you either happened.

Publishing MTA-STS without TLS-RPT means enforcing a policy you cannot see the effects of.
