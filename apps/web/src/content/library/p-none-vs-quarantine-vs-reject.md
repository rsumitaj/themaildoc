---
title: "DMARC p=none vs quarantine vs reject"
description: "What each DMARC policy actually does to your mail, how long to spend at each, and how to move up without losing messages you meant to send."
keyword: "p=none vs quarantine vs reject"
heading: "p=none, quarantine or reject?"
standfirst: "Three policies, one of which protects nothing. What each does to your mail and how to move between them without breaking anything."
kind: cluster
pillar: dmarc-guide
updated: 2026-08-13
published: 2026-08-13
tools: ["dmarc-checker", "spoofability", "dmarc-report-analyzer"]
related: ["dmarc-guide", "how-to-set-up-dmarc", "what-is-dmarc"]
faq:
  - q: "Is p=none better than no DMARC at all?"
    a: "For visibility, yes: it turns on reporting and shows you who sends as your domain. For protection, no. A domain at p=none is exactly as spoofable as a domain with no record, because the policy tells receivers to change nothing."
  - q: "Should I use quarantine or go straight to reject?"
    a: "Quarantine first if real mail depends on the domain, because a mistake puts a message in a spam folder where somebody can retrieve it. A mistake at reject means the message is gone and the sender gets a bounce."
  - q: "How long between each step?"
    a: "Long enough to see a full billing cycle, so two to four weeks per step for most domains. You are waiting for the monthly invoice run and the quarterly newsletter to appear in the reports, not for a fixed time to pass."
  - q: "What if I move to reject and something breaks?"
    a: "Move back to quarantine, find the sender in the reports, authorise it, then move up again. DNS changes take minutes to propagate and this is a normal part of the process rather than a failure."
---

DMARC has three policies. Only two of them do anything to mail.

## p=none

Receivers change nothing. Mail that fails authentication is delivered exactly as it would have been, and a report is sent.

**Use it** as your first record, for two to four weeks, with a working `rua` address. The reports show every system sending as your domain, including the ones nobody remembers signing up for.

**Do not stay there.** A domain at `p=none` is as spoofable as a domain with no DMARC record. The reporting is real; the protection is not. This is the single most common state for a domain that has "done DMARC".

## p=quarantine

Mail that fails goes to the spam folder rather than the inbox.

**Use it** as the middle step, and as a permanent state only if you genuinely cannot get to reject. It stops the attack that matters in practice, because almost nobody acts on an invoice they found in spam.

Its real virtue is that mistakes are recoverable. If you authorise a sender wrongly, the message is in a folder somebody can look in.

## p=reject

Mail that fails is refused at the SMTP conversation. It does not arrive anywhere and the sender gets a bounce.

**Use it** once your reports show only mail you do not recognise failing. This is the goal, and it is what the bulk sender requirements are steering everybody towards.

Mistakes here are not recoverable. A message refused is gone, and the person who sent it gets a technical bounce they will not understand.

## Moving up without breaking anything

Publish `p=none` with `rua`. Wait for a full billing cycle. Read the reports and list every source that failed.

For each one, decide: is this us? If yes, authorise it, by adding it to SPF or getting it to sign with DKIM. If no, leave it failing. That is the mail you are about to start blocking.

When the only failures left are ones you do not recognise, go to `p=quarantine`. Wait again. Then `p=reject`.

Set `sp` at every step. It governs subdomains, and a weaker `sp` means an attacker spoofs `invoices.yourcompany.com` instead, which looks just as convincing.

## Testing without consequences

The `t` tag makes receivers apply `p=none` regardless of your published policy. Publishing `p=reject; t=y` lets you see how enforcement would behave with none of the risk.

Remember to remove it. `p=reject; t=y` protects nothing, and it is the most common reason somebody is certain they are protected when they are not. [The DMARC checker](/lab/dmarc-checker) flags it explicitly.

## Where are you now

[Check your current policy](/lab/dmarc-checker), including one inherited from a parent domain. To read the reports that tell you when it is safe to move up, [Bloodwork](/bloodwork) parses them in your browser without uploading anything.
