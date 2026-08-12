---
title: "DKIM (DomainKeys Identified Mail) Definition"
description: "DKIM is a cryptographic signature on outgoing mail, verified against a public key in DNS. Definition, selectors, and why it survives forwarding."
keyword: "DKIM definition"
term: "DKIM"
definition: "DomainKeys Identified Mail: a cryptographic signature added to outgoing messages and verified against a public key published in the sending domain's DNS. Defined in RFC 6376."
updated: 2026-08-13
seeAlso: ["spf", "dmarc", "dmarc-alignment"]
tools: ["dkim-checker"]
related: ["what-is-dkim"]
---

**DomainKeys Identified Mail.** A signature proving a message was sent by somebody holding the private key, and that it has not been altered in transit.

The public key lives at `<selector>._domainkey.<domain>`. The selector is a label allowing one domain to publish several keys, which is how providers rotate them without downtime.

DKIM's practical advantage over [SPF](/glossary/spf) is that it survives forwarding. When a mailing list relays a message the sending IP changes and SPF breaks; the signature travels with the message and still verifies.

An empty `p=` in the key record is not a broken record. RFC 6376 section 3.6.1 defines it as an explicit revocation, and every signature made with that key must be treated as failing.
