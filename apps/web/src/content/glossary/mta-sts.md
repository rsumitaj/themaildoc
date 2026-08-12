---
title: "MTA-STS Definition: SMTP transport security"
description: "MTA-STS lets a domain require TLS for inbound mail and pin its mail servers. Definition, how the policy is fetched, and what it prevents."
keyword: "MTA-STS definition"
term: "MTA-STS"
definition: "SMTP MTA Strict Transport Security: a policy published over HTTPS and announced in DNS that tells sending servers to require TLS and to accept only named mail exchangers for a domain. Defined in RFC 8461."
updated: 2026-08-13
seeAlso: ["tls-rpt", "dane", "dnssec"]
tools: ["mta-sts-checker", "mta-sts-generator"]
related: []
---

**SMTP MTA Strict Transport Security.** A way for a domain to state that mail arriving at it must be delivered over TLS, to servers it names.

It has two parts. A TXT record at `_mta-sts.<domain>` announces that a policy exists and carries an id that changes when the policy does. The policy itself is fetched over HTTPS from `https://mta-sts.<domain>/.well-known/mta-sts.txt` and lists the permitted mail exchangers and a mode.

The attack it prevents is stripping: an attacker in the network path removing the STARTTLS offer so mail is delivered in the clear. Without a policy, a sending server will usually fall back to an unencrypted connection rather than fail.

`mode: testing` reports problems and changes nothing. `mode: enforce` makes senders refuse delivery when the policy is not met. RFC 8461 section 3.3 forbids redirects on the policy fetch, which is a common misconfiguration when the policy is served by a general web host.
