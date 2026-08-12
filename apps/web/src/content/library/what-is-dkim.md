---
title: "What Is DKIM? DKIM Records Explained Simply"
description: "DKIM signs your mail with a key only you hold. What the record contains, why key length matters, and why DKIM survives forwarding when SPF does not."
keyword: "what is DKIM"
heading: "What is DKIM?"
standfirst: "A cryptographic signature on every message you send, and the only identifier that survives being forwarded."
kind: cluster
pillar: email-authentication-guide
updated: 2026-08-13
published: 2026-08-13
tools: ["dkim-checker", "dmarc-checker"]
related: ["what-is-spf", "what-is-dmarc", "email-authentication-guide"]
faq:
  - q: "What is a DKIM selector?"
    a: "A label that lets one domain publish several keys. The selector appears in the message's DKIM-Signature header as s=, and the key lives at that selector under _domainkey on your domain. Selectors are how providers rotate keys without downtime."
  - q: "How do I find my DKIM selector?"
    a: "Open a message you sent, view its full headers, and read the s= value in the DKIM-Signature line. There is no way to enumerate selectors from DNS, which is why a checker can only probe the ones providers commonly use."
  - q: "Is a 1024-bit DKIM key still safe?"
    a: "It is weak. RFC 8301 sets 1024 as the floor and recommends 2048, and most providers moved years ago. A 1024-bit key is not being factored casually, but there is no reason to keep one."
  - q: "What does an empty p= mean?"
    a: "The key has been revoked. RFC 6376 section 3.6.1 defines a key record with an empty p= value as explicitly withdrawn, and receivers must treat every signature made with it as failing."
---

DKIM adds a cryptographic signature to your mail. The private key stays with your sending system; the public key goes in DNS so receivers can check the signature. Defined in [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376).

## How it works

Your mail server signs each outgoing message with a private key, covering the body and selected headers. The signature goes into a `DKIM-Signature` header.

The receiver reads the domain (`d=`) and selector (`s=`) from that header, fetches the public key from `<selector>._domainkey.<domain>`, and verifies the signature.

Two things follow if it verifies: somebody holding the private key sent it, and the message has not been altered since.

## Selectors

A selector is a label that lets one domain publish more than one key. `google._domainkey.yourcompany.com` and `s1._domainkey.yourcompany.com` can both exist and both be valid.

That is how key rotation works without downtime: publish the new key at a new selector, switch signing over, remove the old one later.

It also means nobody can enumerate your selectors from DNS. You have to read one from a message you sent, which is why [the DKIM checker](/lab/dkim-checker) probes the selectors that common providers use and tells you honestly when it finds nothing.

## Why DKIM matters more than SPF

DKIM survives forwarding. SPF does not.

When a mailing list or a forwarding rule relays your message, the sending IP becomes the forwarder's. That IP is not in your SPF record, so SPF fails. The DKIM signature travels with the message and still verifies.

A domain relying on SPF alone loses DMARC on every forwarded message. That is the practical argument for having both.

## Reading the record

```
v=DKIM1; k=rsa; p=MIGfMA0GCSq...
```

`p=` is the public key. An **empty** `p=` is not a broken record: [RFC 6376 section 3.6.1](https://www.rfc-editor.org/rfc/rfc6376#section-3.6.1) defines it as an explicit revocation, and receivers must treat every signature made with that key as failing.

Key length is the other thing worth checking. [RFC 8301](https://www.rfc-editor.org/rfc/rfc8301) sets 1024 bits as the floor and recommends 2048. Plenty of domains are still signing with keys published before that and nobody has looked since.

## Check yours

[Run the DKIM checker](/lab/dkim-checker). It probes the common selectors, reads the real key length from the published key, and flags a revoked one.
