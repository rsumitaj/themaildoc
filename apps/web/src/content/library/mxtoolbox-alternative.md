---
title: "MXToolbox Alternative: free, no signup"
description: "A free MXToolbox alternative for email authentication: SPF, DKIM, DMARC, MX, DNSSEC and BIMI in one checkup, with the fix for each and no account."
keyword: "MXToolbox alternative"
heading: "Looking for an MXToolbox alternative"
standfirst: "What this does differently, what it does not do at all, and an honest note on when the other one is the right tool."
kind: cluster
pillar: email-deliverability-guide
updated: 2026-08-13
published: 2026-08-13
tools: ["spf-checker", "dmarc-checker", "dkim-checker", "mx-lookup", "spoofability"]
related: ["email-authentication-guide", "why-are-my-emails-going-to-spam"]
faq:
  - q: "Is this really free?"
    a: "Yes, with no account and no paid tier holding the real answer back. Every check reads public DNS, which costs nothing to query, and the site runs on a free hosting tier. There is a consultancy link because that is how the work behind it gets paid for."
  - q: "Do you do blacklist checks?"
    a: "Not yet. Blacklist lookups need a query per list per address and most of the useful lists rate-limit or forbid public querying from shared infrastructure. Rather than ship one that silently checks four lists and implies it checked forty, it is not here."
  - q: "What do you do that MXToolbox does not?"
    a: "Three things. The SPF chain is walked all the way down with the exact lookup count, so you see which vendor is spending your budget. BIMI is checked by fetching the logo and the certificate rather than reading the DNS record, which catches expired certificates. And every finding cites and links the RFC section it comes from."
---

MXToolbox has been the default for fifteen years and it does a great deal this does not. If you need blacklist monitoring across dozens of lists, SMTP diagnostics or alerting, use it.

Here is what is different about this one.

## Everything at once, then the fix

Enter a domain and get SPF, DKIM, DMARC, MX, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA and reverse DNS in one pass, scored, with the exact record to publish for each problem.

Most checkers tell you what a record says. This tells you what to change and gives you the string to paste.

## The SPF chain, expanded

SPF allows ten DNS lookups and the ones inside your includes count against the same ten. A record with four entries can be over the limit through a vendor.

[The SPF checker](/lab/spf-checker) walks the entire chain, shows the cost of every branch, and gives the exact count. When a walk cannot be completed it says so rather than reporting a smaller number as fact.

## BIMI checked properly

A BIMI record is two URLs. Reading the record and calling it valid is what nearly every checker does, which is why domains whose verified mark certificate expired months ago still get a green tick.

[The BIMI checker](/lab/bimi-checker) fetches the logo and the certificate, checks the SVG profile, and reads the real expiry date.

## Every finding cites its source

Each condition links the RFC section it comes from, so you can check the tool rather than trust it. That matters more than it sounds: a lot of email advice on the internet is confidently wrong, including advice about tags that were removed from the standard.

## What is not here

No blacklist checking, for now, and the reason is above. No SMTP connection tests, because a serverless function cannot open port 25. No inbox placement testing, because that needs seed accounts at every provider and anybody offering it free is estimating.

No monitoring or alerting either. This is a diagnostic, not a dashboard.

## Try it

[Run the checkup](/checkup), or pick one test from [the Lab](/lab). No account, and nothing about a checkup is stored.
