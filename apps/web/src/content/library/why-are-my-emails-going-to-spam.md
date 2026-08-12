---
title: "Why Are My Emails Going to Spam? The 6 Real Causes"
description: "Your email is landing in spam. Here are the six causes in the order worth checking, how to tell which one you have, and the free test that proves it."
keyword: "why are my emails going to spam"
heading: "Why are my emails going to spam?"
standfirst: "Six causes, in the order worth checking. The first two you can prove in about a minute; the rest take longer and matter less often."
kind: cluster
pillar: email-deliverability-guide
updated: 2026-08-13
published: 2026-08-13
tools: ["spf-checker", "dmarc-checker", "sender-readiness"]
related: ["email-deliverability-guide", "google-yahoo-microsoft-sender-requirements-2026", "how-to-fix-spf-too-many-dns-lookups"]
faq:
  - q: "Why do my emails go to spam only for Gmail users?"
    a: "Gmail weights authentication and complaint rate more heavily than most, and since 2024 it rejects non-compliant bulk mail outright rather than filtering it. If Gmail is the only one refusing you, check the bulk sender requirements first: one-click unsubscribe and a complaint rate under 0.3 percent are the two that catch people."
  - q: "Why did my email start going to spam all of a sudden?"
    a: "Something changed. In order of likelihood: a DNS record was edited, a new sending tool was added without being authorised in SPF or DKIM, a list was imported, or your volume jumped sharply. Check DNS first because it takes seconds to rule out."
  - q: "Can one bad email campaign ruin my domain?"
    a: "One can start it. A campaign to a purchased list that generates complaints and hits spam traps damages a domain reputation quickly, and rebuilding takes weeks of well-received sending. It is recoverable, but slowly."
  - q: "Does an unsubscribe link help or hurt?"
    a: "It helps, considerably. A person who unsubscribes costs you nothing; a person who cannot find the link presses the spam button instead, and that is the single most damaging signal you can generate."
---

Mail landing in spam has a short list of causes. Work through them in this order, because the first two are provable in seconds and the rest are not.

## 1. Your authentication is broken

The most common single cause, and the only one you can verify rather than guess at.

Broken means one of: no DMARC record, or one at `p=none` that nothing enforces; an SPF record over the ten DNS lookup limit, which fails for every message you send; a DKIM key rotated at the provider and never updated in DNS.

[Run the checkup](/checkup). It takes about five seconds and either eliminates this cause or hands you the exact record to publish.

## 2. You are breaking the bulk sender rules

If you send more than five thousand messages a day to Gmail, Yahoo or Microsoft, they enforce a published list of requirements with rejections rather than filtering. The ones that catch people are one-click unsubscribe and a spam complaint rate under 0.3 percent.

[Test what is visible in DNS](/lab/sender-readiness). The rest, complaint rate in particular, has to come from your sending platform.

## 3. Your list is the problem

Sending to addresses that never asked is the fastest way to ruin a working domain. Purchased lists contain spam traps deliberately, and hitting one is a direct route to a blocklist.

Old lists do it slowly. Addresses go dead, some get recycled into traps, and a high bounce rate tells receivers you are not maintaining anything.

## 4. Your volume changed

Going from two hundred messages a day to twenty thousand looks exactly like a compromised account. Receivers respond to the shape of the change, not your intentions.

New domains and new IPs have no reputation at all, which is treated as suspicious rather than neutral. Ramp over weeks.

## 5. Your sending IP has no reverse DNS

Every serious receiver checks that the IP connecting to them has a PTR record, and that the name in that record resolves back to the same IP. A sending IP failing that check is treated as unconfigured infrastructure.

[Check the reverse DNS](/lab/reverse-dns) on your sending IP. If you send through a provider this is their job, and it is usually already right.

## 6. The content

Last on the list because it is where most advice starts and it matters least.

What still counts: send a plain text alternative alongside HTML, point links at domains related to the sender rather than through redirect chains, do not make the entire message one image, and use a From address at a domain that can actually receive replies.

## Which one is yours

If your mail was fine and suddenly stopped, it is 1, 3 or 4, and DNS is the fastest to eliminate.

If your mail has never worked properly, it is 1 or 2.

If the checkup comes back clean and mail is still landing in spam, you are in 3 or 4, and neither is visible from outside your sending platform. That is the point at which [an hour with somebody who reads aggregate reports for a living](/practice) is cheaper than another week of guessing.
