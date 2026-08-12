---
title: "What Is SPF? SPF Records Explained Simply"
description: "SPF lists the servers allowed to send for your domain. What the record means, what each mechanism costs, and the limit that breaks most records."
keyword: "what is SPF"
heading: "What is SPF?"
standfirst: "A published list of the servers allowed to send for your domain, and the ten-lookup limit that quietly breaks a lot of them."
kind: cluster
pillar: email-authentication-guide
updated: 2026-08-13
published: 2026-08-13
tools: ["spf-checker", "spf-generator", "spf-flattener"]
related: ["how-to-fix-spf-too-many-dns-lookups", "spf-permerror-explained", "email-authentication-guide", "what-is-dkim"]
faq:
  - q: "What does an SPF record look like?"
    a: "A TXT record at your domain starting v=spf1, then the servers you authorise, then a policy for everything else. For example v=spf1 include:_spf.google.com -all authorises Google Workspace and rejects everything else."
  - q: "What is the difference between ~all and -all?"
    a: "~all is softfail: mail from an unlisted server is marked suspicious but usually delivered. -all is hardfail: it should be refused. -all is the goal, but only once you are certain every legitimate sender is listed."
  - q: "Can I have two SPF records?"
    a: "No. Two v=spf1 records at the same name is a permanent error and receivers treat SPF as broken entirely. If you need to authorise more senders, merge them into one record."
  - q: "Does SPF survive forwarding?"
    a: "No, and that is its main weakness. When a message is forwarded the sending IP changes to the forwarder's, which is not in your record, so SPF fails. DKIM survives forwarding, which is why you need both."
---

SPF is a TXT record listing the servers allowed to send mail for your domain. Defined in [RFC 7208](https://www.rfc-editor.org/rfc/rfc7208).

## Reading one

```
v=spf1 include:_spf.google.com ip4:203.0.113.10 -all
```

`v=spf1` opens every SPF record. Then a list of things that authorise a sender, then a policy for everything not listed.

`include:` pulls in another domain's record, which is how you authorise a provider. `ip4:` and `ip6:` authorise addresses directly. `a` and `mx` authorise whatever your A or MX records point at.

`-all` at the end means everything else fails. `~all` means everything else is suspicious but probably deliverable. The `all` mechanism is always last, and anything after it is ignored.

## What SPF proves, and what it does not

SPF checks the envelope sender, the address in the `MAIL FROM` part of the SMTP conversation. Your recipient never sees that address.

So SPF on its own does not stop somebody putting your domain in the From header. It proves a particular server was allowed to send for a particular envelope domain, which is narrower than most people assume. Tying it to the visible address is [DMARC's job](/health-library/what-is-dmarc).

## The ten lookup limit

This is where most SPF records go wrong.

Each `include`, `a`, `mx`, `ptr`, `exists` and `redirect` costs one DNS lookup, and the lookups inside your includes count against the same total. Ten is the maximum, from [RFC 7208 section 4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4). Past it, receivers must return a permanent error, and SPF fails for every message you send.

A record with four entries can be over the limit because one vendor's record contains six of its own. You cannot tell by looking at it, which is why [the checker](/lab/spf-checker) expands the whole chain and shows the cost of each branch. If you are over, [how to get back under](/health-library/how-to-fix-spf-too-many-dns-lookups).

## Two rules people break

**Never publish two SPF records.** Two `v=spf1` records at the same name is a permanent error and receivers treat SPF as broken entirely. Merge them.

**Never use `+all`.** It authorises every server on the internet to send as you. It appears when somebody is trying to make an error go away, and it is worse than having no record.

## Check yours

[Run the SPF checker](/lab/spf-checker) for the exact lookup count and the chain that produced it. Building a first record: [the generator](/lab/spf-generator).
