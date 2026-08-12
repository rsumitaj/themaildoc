---
title: "Email Authentication Guide: SPF, DKIM and DMARC"
description: "How SPF, DKIM and DMARC actually work together, what each one proves, and the order to fix them in. Written from the RFCs, with the checks to prove it."
keyword: "email authentication"
heading: "Email authentication, explained by what each part proves"
standfirst: "Three records, three different jobs, and only one of them stops somebody sending mail in your name. Here is what each proves and the order to fix them in."
kind: pillar
updated: 2026-08-13
published: 2026-08-13
tools: ["spf-checker", "dkim-checker", "dmarc-checker", "spoofability"]
related: ["what-is-spf", "what-is-dkim", "what-is-dmarc", "dmarc-guide"]
faq:
  - q: "Do I need all three of SPF, DKIM and DMARC?"
    a: "Yes, and in that order. SPF and DKIM each prove something narrow and neither of them looks at the address your recipient sees. DMARC is the record that ties them to that address and tells receivers what to do when neither one holds up. Publishing SPF and DKIM without DMARC is common and it leaves the door open."
  - q: "Which one stops email spoofing?"
    a: "DMARC, and only when its policy is quarantine or reject. SPF and DKIM authenticate parts of a message that a recipient never sees, so on their own they do not stop anybody putting your domain in the From line."
  - q: "What order should I fix them in?"
    a: "SPF first, because it is the easiest to get wrong and the quickest to verify. DKIM next, because it is the one that survives forwarding. DMARC last, at p=none with a reporting address, then move it up once the reports show only senders you recognise."
  - q: "Can I skip SPF if I have DKIM?"
    a: "You can pass DMARC on DKIM alone, and some large senders deliberately do. It is still worth publishing SPF: some receivers check it independently of DMARC, and a domain with no SPF record at all gives a spammer one less thing to trip over."
---

Three records, three jobs. Most guides describe them as three ways of doing the same thing, which is why so many domains publish all three and are still spoofable.

## What each one actually proves

**SPF** proves that a particular server was allowed to send. It checks the envelope sender, the address in the SMTP conversation, not the address your recipient reads. Defined in [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208).

**DKIM** proves that a message was signed by somebody holding a private key, and that it has not been altered since. It says nothing about which server sent it. Defined in [RFC 6376](https://www.rfc-editor.org/rfc/rfc6376).

**DMARC** is the only one that looks at the From address your recipient sees. It asks whether SPF or DKIM passed *for that domain*, and tells receivers what to do when neither did. Defined in [RFC 9989](https://www.rfc-editor.org/rfc/rfc9989).

That last point is the one that matters. Anyone can put your domain in the From header. SPF and DKIM do not stop them, because neither looks there. Only DMARC does, and only when it is set to quarantine or reject.

## Alignment is the part people miss

DMARC does not just ask "did SPF pass". It asks "did SPF pass *for the domain in the From header*". That second condition is called alignment, and it is where most half-configured domains fail.

A message can pass SPF for `mailer.vendor.com`, be signed by `vendor.com`, and still fail DMARC for `yourcompany.com`, because neither identifier lines up with the domain the recipient sees. The message authenticated perfectly. It just authenticated somebody else.

This is why adding a vendor to your SPF record does not make their mail pass DMARC. The vendor has to either send with your domain in the envelope sender, or sign with a key published in your DNS.

## The order to fix them in

**SPF first.** It is the fastest to verify and the easiest to get wrong. The trap is the ten DNS lookup limit in [RFC 7208 section 4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4): the lookups inside your includes count against the same ten, so a record with four entries can be over the limit through somebody else's vendor. Past ten, receivers return a permanent error and SPF fails for every message you send.

**DKIM second.** It is the identifier that survives forwarding. When a mailing list or a forwarding rule relays your message, the sending IP changes and SPF breaks. The signature does not. A domain relying on SPF alone loses DMARC on every forwarded message.

**DMARC last**, and start at `p=none` with a reporting address. That publishes nothing that can break your mail while it collects a fortnight of evidence about who sends as you. Read it, fix what you find, then move up.

## What each record cannot do

None of this touches content filtering. A domain with perfect authentication can still land in spam because of what it says, how often it sends, or how many people mark it as junk. Authentication is the gate, not the whole road.

None of it encrypts anything either. That is MTA-STS and TLS-RPT, which govern how mail travels rather than who is allowed to send it.

And DMARC does not protect lookalike domains. If somebody registers `yourcornpany.com`, no record you publish will stop them. What DMARC stops is the use of your exact domain, which is the attack that actually convinces a finance team.

## Check yours

Run the [full checkup](/checkup) to see all three at once with the exact fix for each, or test one at a time: [SPF](/lab/spf-checker), [DKIM](/lab/dkim-checker), [DMARC](/lab/dmarc-checker). If you only want one answer, [can somebody send as you right now](/lab/spoofability).
