---
title: "p=reject Definition: the DMARC policy"
description: "p=reject tells receivers to refuse mail that fails DMARC. Definition, what it protects, and what to check before publishing it."
keyword: "p=reject"
term: "p=reject"
definition: "The DMARC policy instructing receivers to refuse messages that fail authentication for the From domain, rather than delivering or quarantining them. Defined in RFC 9989 section 4.7."
updated: 2026-08-13
seeAlso: ["dmarc", "dmarc-alignment", "spf", "dkim"]
tools: ["dmarc-checker", "spoofability"]
related: ["p-none-vs-quarantine-vs-reject", "how-to-set-up-dmarc"]
---

The DMARC policy that actually stops impersonation. Mail failing authentication for your domain is refused during the SMTP conversation: it does not arrive anywhere, and the sender receives a bounce.

This is the goal state, and it is what the bulk sender requirements are steering everybody towards.

Two things to check before publishing it. Every legitimate sender must be authorised, which you establish by reading aggregate reports at `p=none` for a full billing cycle rather than by memory. And `sp` should be set explicitly, because a weaker subdomain policy means an attacker spoofs `invoices.yourcompany.com` instead, which looks just as convincing in an inbox.

Mistakes at reject are not recoverable. A refused message is gone, and whoever sent it gets a technical bounce they will not understand. That is the argument for spending time at `quarantine` first, where a mistake lands somewhere retrievable.

`p=reject; t=y` protects nothing: the `t` tag makes receivers apply `p=none` regardless. It is the most common reason a domain owner is certain they are protected when they are not.
