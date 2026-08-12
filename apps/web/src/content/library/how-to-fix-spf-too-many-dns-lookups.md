---
title: "Fix SPF Too Many DNS Lookups (PermError)"
description: "SPF allows ten DNS lookups and the ones inside your includes count too. How to see your real count, and the four ways to get back under the limit."
keyword: "SPF too many DNS lookups"
heading: "SPF: too many DNS lookups"
standfirst: "Ten is the limit, the lookups inside your includes count against it, and past ten SPF fails for every message you send. Here is how to get back under."
kind: cluster
pillar: email-authentication-guide
updated: 2026-08-13
published: 2026-08-13
tools: ["spf-checker", "spf-flattener", "spf-generator"]
related: ["what-is-spf", "spf-permerror-explained", "email-authentication-guide"]
steps:
  - name: "Count what you actually use"
    text: "Run the SPF checker to see the whole chain expanded, with the cost of every include. The count that matters includes lookups inside your vendors' records, not just the entries you wrote."
  - name: "Remove the vendors you no longer use"
    text: "This alone usually solves it. Most records over the limit contain at least one include for a tool nobody has sent from in two years."
  - name: "Replace includes with the ip4 and ip6 ranges behind them"
    text: "ip4 and ip6 mechanisms cost nothing against the limit. Flattening a vendor include into its addresses buys back the whole lookup."
  - name: "Move senders onto a subdomain"
    text: "A subdomain gets its own SPF record and its own ten lookups. Marketing mail from news.yourcompany.com stops competing with your transactional mail."
faq:
  - q: "What is the SPF lookup limit?"
    a: "Ten. RFC 7208 section 4.6.4 caps the DNS-querying mechanisms at ten per evaluation, counting include, a, mx, ptr and exists, plus redirect. ip4, ip6 and all cost nothing. Past ten, receivers must return a permanent error."
  - q: "What happens when I exceed it?"
    a: "SPF returns PermError, which counts as a failure rather than a pass. Every message you send fails SPF from that moment, and if you rely on SPF for DMARC alignment, DMARC fails with it."
  - q: "Is flattening SPF safe?"
    a: "It works and it needs maintaining. When you replace an include with the addresses behind it, you take on the job of updating them when the vendor changes their ranges, and they do not tell you. Flatten the vendors that rarely change and leave the rest."
  - q: "Does the void lookup limit matter too?"
    a: "Yes. Two lookups returning nothing is also a permanent error, and it is a separate limit from the ten. It usually means an include pointing at a vendor whose record no longer exists."
---

SPF allows ten DNS lookups per evaluation. The limit is in [RFC 7208 section 4.6.4](https://www.rfc-editor.org/rfc/rfc7208#section-4.6.4), and it is not advisory: a receiver that goes past ten must return a permanent error.

The part that catches people is that the lookups inside your includes count against the same ten. A record with four entries in it can be over the limit because one vendor's record contains six of its own.

## How to see your real count

Guessing from the length of your record does not work. [The SPF checker](/lab/spf-checker) walks the entire chain, expands every include, and shows what each one costs.

You are looking for two numbers: the total, and which branch is spending it.

## What counts and what does not

Each of `include`, `a`, `mx`, `ptr`, `exists` and `redirect` costs one lookup, every time it is evaluated, at any depth.

`ip4`, `ip6` and `all` cost nothing. They are answered from the record you already fetched.

That asymmetry is the whole basis of every fix below.

## The four ways back under

**Remove what you do not use.** This alone solves most cases. Nearly every over-limit record contains an include for a tool nobody has sent from in years. Removing it costs nothing and risks nothing.

**Flatten the stable vendors.** Replace an `include` with the `ip4` and `ip6` ranges behind it and you buy back a whole lookup, because addresses are free. The trade is maintenance: when the vendor changes their ranges they will not tell you, and your record will silently stop authorising their mail. Flatten the ones that rarely move, leave the volatile ones alone. [The flattener](/lab/spf-flattener) does the expansion and refuses to hand you a record it could not resolve completely.

**Split onto subdomains.** A subdomain gets its own SPF record and its own budget of ten. Sending marketing from `news.yourcompany.com` takes its includes out of competition with your transactional mail entirely. This is the cleanest fix and the one large senders use.

**Lean on DKIM instead.** DMARC passes on SPF *or* DKIM. If your vendors sign with a key published in your DNS, their mail aligns without appearing in your SPF record at all. This is the only fix that removes the pressure permanently.

## Two things not to do

Do not raise the limit. You cannot; it is enforced by the receiver, not by you.

Do not end the record with `+all` to make the error go away. That authorises every server on the internet to send as you, which is worse than the problem you started with.

## Check it

[Run the SPF checker](/lab/spf-checker) for the exact count and the chain that produced it. If you are over, [the flattener](/lab/spf-flattener) will show you what the record looks like once the expandable parts are expanded.
