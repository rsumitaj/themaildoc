---
title: "PTR and FCrDNS Definition for mail servers"
description: "A PTR record names an IP address; forward-confirmed reverse DNS checks the name points back. Definition and why receivers require both."
keyword: "FCrDNS"
term: "PTR and FCrDNS"
definition: "A PTR record maps an IP address to a hostname; forward-confirmed reverse DNS (FCrDNS) is the check that the hostname resolves back to the same address. Receivers use it to distinguish configured mail infrastructure from arbitrary hosts."
updated: 2026-08-13
seeAlso: ["spf", "dmarc"]
tools: ["reverse-dns"]
related: ["email-deliverability-guide"]
---

A **PTR** record answers "what is this IP address called". It lives in the reverse DNS tree under `in-addr.arpa` and is controlled by whoever holds the IP block, which is your hosting provider rather than you.

**FCrDNS**, forward-confirmed reverse DNS, is the round trip: take the IP, find its PTR name, resolve that name, and confirm it comes back to the same IP. Anybody can point a name at an address they do not own, so the forward confirmation is what makes the answer mean something.

Mail receivers treat a sending IP that fails this as unconfigured infrastructure, and it is one of the explicit requirements the large providers publish for bulk senders. RFC 1912 section 2.1 has asked for consistent forward and reverse records since 1996.

If you send through a provider, this is their responsibility and it is usually already correct. If you run your own mail server, it is a support ticket to whoever gave you the IP.
