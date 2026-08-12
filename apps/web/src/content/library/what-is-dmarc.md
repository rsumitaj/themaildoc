---
title: "What Is DMARC? A Plain English Explanation"
description: "DMARC is the record that decides what happens to mail claiming to be from you. What it does, what it does not, and how to read one."
keyword: "what is DMARC"
heading: "What is DMARC?"
standfirst: "The only email record that looks at the address your recipient actually sees, and the only one that stops somebody sending in your name."
kind: cluster
pillar: dmarc-guide
updated: 2026-08-13
published: 2026-08-13
tools: ["dmarc-checker", "spoofability", "dmarc-generator"]
related: ["dmarc-guide", "how-to-set-up-dmarc", "p-none-vs-quarantine-vs-reject", "what-is-spf"]
faq:
  - q: "What does DMARC stand for?"
    a: "Domain-based Message Authentication, Reporting and Conformance. The name describes the three things it does: it ties authentication to the visible From domain, it tells receivers what to do on failure, and it asks them to report back."
  - q: "Is DMARC required?"
    a: "Not by any standard, but effectively yes if you send in volume. Google, Yahoo and Microsoft all require a DMARC record from bulk senders and reject mail from domains without one."
  - q: "Does DMARC stop all phishing?"
    a: "It stops mail using your exact domain in the From address. It does nothing about a lookalike domain somebody registered last week, and nothing about a display name reading your company with a webmail address behind it."
  - q: "Can DMARC break my email?"
    a: "At p=reject, yes, if a system you forgot about sends as you and is not authorised. That is exactly why you start at p=none and read the reports before enforcing anything."
---

DMARC is a TXT record at `_dmarc.yourcompany.com` that answers one question: what should a receiver do with mail claiming to be from you that cannot prove it?

## The problem it solves

Anyone can put your domain in the From line of an email. Nothing in the original mail protocols prevents it, and SPF and DKIM do not either, because neither of them looks at that header.

SPF checks the envelope sender, which recipients never see. DKIM checks a signature, which says who signed but not who the message claims to be from. A message can pass both and still display your company name in an inbox while having nothing to do with you.

DMARC closes that gap. It requires that SPF or DKIM passed **for the domain in the From header**, and it tells receivers what to do when neither did.

## Reading a record

```
v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@yourcompany.com
```

`v=DMARC1` must be exactly that, case included. Anything else and receivers ignore the whole record.

`p` is the policy for the domain itself. `none` means report but deliver. `quarantine` means treat as suspicious, usually the spam folder. `reject` means refuse at the door.

`sp` is the policy for subdomains. If you leave it out it inherits from `p`, and if you set it weaker than `p` an attacker just spoofs `invoices.yourcompany.com` instead.

`rua` is where daily aggregate reports are sent.

## What p=none actually means

`p=none` tells receivers to change nothing. Deliver the mail as you would have anyway, and send a report.

It is the correct place to start, because the reports show you every system sending as your domain before you block any of them. It is not protection. A domain sitting at `p=none` is exactly as spoofable as a domain with no DMARC record at all, and a large share of domains that publish DMARC never move past it.

## What it will not do

DMARC does not stop lookalike domains. `yourcornpany.com` with an r and an n is a different domain and no record you publish governs it.

It does not stop display name spoofing, where the sender name reads as your CEO and the actual address is a webmail account.

It does not encrypt anything, and it does not improve your reputation. It stops the specific attack of somebody using your exact domain, which is the one that convinces a finance team to pay an invoice.

## Check yours

[Test your DMARC record](/lab/dmarc-checker), including the policy receivers actually apply if yours is inherited from a parent domain. Or skip to the blunt version: [can somebody send as you right now](/lab/spoofability).
