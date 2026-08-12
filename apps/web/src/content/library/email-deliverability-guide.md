---
title: "Email Deliverability Guide: why mail lands in spam"
description: "Why legitimate email ends up in spam, in the order worth checking: authentication, reputation, list hygiene and content. With the test for each."
keyword: "email deliverability"
heading: "Why your mail lands in spam, in the order worth checking"
standfirst: "Deliverability problems have a small number of causes and a reliable order to work through them. Authentication first, because it is the only part you can prove."
kind: pillar
updated: 2026-08-13
published: 2026-08-13
tools: ["spf-checker", "dmarc-checker", "sender-readiness", "reverse-dns", "mx-lookup"]
related: ["why-are-my-emails-going-to-spam", "google-yahoo-microsoft-sender-requirements-2026", "email-authentication-guide"]
faq:
  - q: "Why did my email suddenly start going to spam?"
    a: "Something changed, and it is usually one of four things: a DNS record was edited, a new sending tool was added without being authorised, a list was imported that had not opted in, or your volume jumped. Start with authentication because it is the only one of the four you can verify in seconds."
  - q: "Does authentication alone fix deliverability?"
    a: "No, and anybody promising that is selling something. Authentication decides whether you are allowed to be considered. Reputation, list quality and content decide where you land after that. What authentication does is remove the one cause you can prove and eliminate in an afternoon."
  - q: "How much does a spam complaint rate matter?"
    a: "It is the number the large receivers act on most directly. Google asks bulk senders to stay under 0.3 percent and treats 0.1 percent as the target. It cannot be read from DNS, so no checking tool can tell you yours. Your sending platform can."
  - q: "Is a dedicated IP better than a shared one?"
    a: "Only above a certain volume. A dedicated IP with low, irregular traffic never builds a reputation, so it is treated as unknown, which is worse than a well-run shared pool. Below roughly a hundred thousand messages a month, shared is usually the better answer."
---

Mail lands in spam for a small number of reasons. Work through them in this order, because the earlier ones are provable and the later ones are judgement.

## 1. Authentication

This is first because it is the only part of deliverability you can verify rather than estimate.

If SPF, DKIM and DMARC are not right, everything downstream is guesswork. Fix them, confirm they are fixed, then look at the rest. Start with the [full checkup](/checkup) or read the [authentication guide](/health-library/email-authentication-guide).

The specific failures worth checking for: an SPF record over the ten lookup limit, which fails for every message you send; a DKIM key that was rotated at the provider and never updated in DNS; a DMARC policy inherited from a parent domain you do not control.

## 2. The bulk sender rules

Since 2024, Google, Yahoo and Microsoft have published explicit requirements for anyone sending in volume, and they enforce them with rejections rather than filtering. If you send more than five thousand messages a day to any of them, these are not advice.

The requirements are authentication, a working one-click unsubscribe, TLS on transmission, valid forward and reverse DNS on your sending IP, and a spam complaint rate under 0.3 percent. The [sender readiness test](/lab/sender-readiness) checks the parts that are visible in DNS and tells you plainly which parts are not.

## 3. Reputation

Receivers keep a score for your domain and your sending IP. It is built from complaint rate, spam trap hits, bounce rate and how people engage.

Nothing in DNS shows you this. What you can check is that the technical groundwork is not undermining it: your sending IP should have a [PTR record that resolves back to itself](/lab/reverse-dns), and your [MX records](/lab/mx-lookup) should point at hosts that actually exist.

Reputation is also why volume changes hurt. Going from two hundred messages a day to twenty thousand looks exactly like a compromised account, so ramp gradually.

## 4. List quality

The fastest way to ruin a good domain is to send to addresses that never asked. Purchased lists contain spam traps by design, and hitting one is a direct route to a blocklist.

Bounces matter as much. A list with a high proportion of dead addresses tells receivers you are not maintaining it, and they respond accordingly.

## 5. Content

Last, because it matters least and gets the most attention. The old advice about avoiding the word "free" has been wrong for a decade.

What still counts: a plain text alternative alongside HTML, links pointing at domains related to the sender rather than a chain of redirectors, images that are not the entire message, and a From address at a domain that actually receives mail.

## The uncomfortable part

Two of these five, reputation and list quality, cannot be measured from outside. Any tool claiming to score your inbox placement from DNS alone is guessing, and this one will not do that.

What can be proved is authentication and the technical requirements the large receivers publish. That is most of the fixable surface, and it is where nearly every "our mail suddenly stopped arriving" ticket ends up.

Start with [the checkup](/checkup). If it comes back clean and mail is still landing in spam, the problem is in the two you cannot see from DNS, and that is worth [an hour with somebody who reads reports for a living](/practice).
