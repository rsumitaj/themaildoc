---
title: "Gmail, Yahoo and Microsoft Sender Rules 2026"
description: "What Google, Yahoo and Microsoft require from bulk senders, which parts are enforced with rejections, and how to check the ones visible in DNS."
keyword: "Gmail Yahoo sender requirements"
heading: "The bulk sender requirements, and which parts bite"
standfirst: "Three receivers, one shared list of requirements, and rejections rather than filtering when you miss them. Here is what each one asks for."
kind: cluster
pillar: email-deliverability-guide
updated: 2026-08-13
published: 2026-08-13
tools: ["sender-readiness", "dmarc-checker", "spf-checker", "reverse-dns"]
related: ["email-deliverability-guide", "why-are-my-emails-going-to-spam", "how-to-set-up-dmarc"]
faq:
  - q: "What counts as a bulk sender?"
    a: "Roughly five thousand messages a day to a single provider. Google counts per Gmail account across your domain, and once you cross the threshold you are treated as a bulk sender from then on, whether or not you drop back below it."
  - q: "What happens if I do not comply?"
    a: "Rejection rather than filtering. Non-compliant bulk mail gets a permanent SMTP error, so the message never arrives and your sending system records a bounce. This is deliberately louder than a spam folder."
  - q: "What complaint rate do they require?"
    a: "Under 0.3 percent, with 0.1 percent as the stated target. It cannot be read from DNS by anyone, so no checking tool can tell you yours. Google Postmaster Tools reports it for Gmail."
  - q: "Do these rules apply to transactional email?"
    a: "The authentication, TLS and DNS requirements apply to everything. One-click unsubscribe applies to promotional mail, not to password resets and receipts, though the line is not always obvious and receivers judge it by content."
---

Google, Yahoo and Microsoft now publish requirements for anyone sending in volume, and they enforce them with rejections rather than filtering. A message that fails does not land in spam. It bounces.

## Who this applies to

Roughly five thousand messages a day to a single provider. Google counts across your domain to Gmail accounts, and once you cross the line you are treated as a bulk sender from then on.

Below that threshold the requirements are still the right configuration. They are simply not enforced against you yet.

## What all three require

**SPF and DKIM.** Both, not either. This is stricter than DMARC itself, which passes on one.

**A DMARC record.** At minimum `p=none`. The record has to exist and be valid.

**Alignment.** The domain in your From header has to line up with the domain that passed SPF or DKIM. A message can pass both and still fail this, which is the most common reason a technically authenticated sender is rejected.

**Valid forward and reverse DNS.** Your sending IP needs a PTR record, and the name in it has to resolve back to the same IP. If you send through a provider this is their job and it is usually already right. [Check it](/lab/reverse-dns).

**TLS on transmission.** Opportunistic TLS is enough; nothing here requires MTA-STS, though publishing it is the stronger position.

**One-click unsubscribe.** For promotional mail, a `List-Unsubscribe` header supporting one-click, honoured within two days. A link in the footer alone is not sufficient.

**A spam complaint rate under 0.3 percent.** The number they act on most directly, with 0.1 percent as the stated target.

## The two you cannot check from DNS

Complaint rate and unsubscribe handling are invisible from outside. Nothing that reads your DNS can tell you either, and any tool claiming to score them is guessing.

Complaint rate comes from Google Postmaster Tools for Gmail, and from your sending platform for the rest. Unsubscribe handling you verify by sending yourself a message and using the header.

[The sender readiness test](/lab/sender-readiness) checks everything that is visible in DNS and states plainly which requirements it cannot see, rather than implying a pass.

## What to do first

Get authentication right, because it is the largest block of requirements and the only part that is provable. [Run the checkup](/checkup).

Then confirm reverse DNS on your sending IP, add one-click unsubscribe to promotional mail, and look at your complaint rate in Postmaster Tools.

If your complaint rate is the problem, no DNS record will fix it. That is a list and content question, and it is the one worth [an hour with somebody who has read a lot of aggregate reports](/practice).
