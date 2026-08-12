---
title: "DMARC Guide: policy, alignment and reporting"
description: "A complete DMARC guide: what the record does, how alignment works, what p=none really protects, and how to reach reject without losing your own mail."
keyword: "DMARC guide"
heading: "DMARC, from a first record to enforcement"
standfirst: "The only record that governs the address your recipient actually sees. What it does, what it does not, and how to reach enforcement without breaking your own mail."
kind: pillar
updated: 2026-08-13
published: 2026-08-13
tools: ["dmarc-checker", "dmarc-generator", "spoofability", "dmarc-report-analyzer"]
related: ["what-is-dmarc", "how-to-set-up-dmarc", "p-none-vs-quarantine-vs-reject", "email-authentication-guide"]
faq:
  - q: "Does p=none protect my domain?"
    a: "No. p=none asks receivers to report what failed and deliver it anyway. It is the right place to start because it shows you who sends your mail before you block anything, but a domain left at p=none is exactly as spoofable as a domain with no DMARC at all."
  - q: "How long should I stay at p=none?"
    a: "Long enough to see a full billing cycle in the reports, so two to four weeks for most domains. You are waiting for the monthly invoice run, the quarterly newsletter and the annual renewal notice to show up, not for a fixed period to elapse."
  - q: "What is the pct tag and should I use it?"
    a: "It was removed in the current standard. RFC 9989 dropped pct along with rf and ri, so receivers ignore it and a staged rollout built on pct is not happening. Use the t tag for testing instead."
  - q: "Why do my DMARC reports never arrive?"
    a: "Usually because the reporting address is at a different domain and that domain has not authorised you. The destination must publish a TXT record at yourdomain._report._dmarc.theirdomain containing v=DMARC1. Without it, receivers silently drop every report."
---

DMARC is the record that decides what happens to mail claiming to be from you. Everything else authenticates something adjacent.

## The record itself

A working record is short:

```
v=DMARC1; p=reject; rua=mailto:dmarc@yourcompany.com
```

Published as a TXT record at `_dmarc.yourcompany.com`. Three tags do almost all of the work.

`v` must be exactly `DMARC1`, case included. Get it wrong and receivers ignore the entire record, including your policy. `p` is the policy: `none`, `quarantine` or `reject`. `rua` is where aggregate reports go.

Everything else is optional and most of it should stay that way. [RFC 9989 section 4.7](https://www.rfc-editor.org/rfc/rfc9989#section-4.7) lists the full set.

## Alignment, which is the whole mechanism

DMARC passes when SPF or DKIM passes **and** the domain it passed for lines up with the domain in the From header. Either one is enough. Both failing is what triggers your policy.

Relaxed alignment, which is the default, accepts a subdomain: mail from `mail.yourcompany.com` aligns with `yourcompany.com`. Strict alignment requires an exact match and will break most vendor setups without warning.

This is why an SPF record listing every vendor you use does not produce a passing DMARC. If the vendor sends with their own domain in the envelope sender, SPF passes for them and aligns with nothing of yours.

## What p=none is for

`p=none` publishes a policy that instructs receivers to do nothing differently. Its value is entirely in the reports.

Two weeks at `p=none` with a working `rua` address tells you every system sending as your domain, including the ones nobody told you about: the CRM someone signed up for, the ticketing system, the payroll provider, the ten-year-old script on a server under a desk. That inventory is the reason to start there.

The mistake is stopping there. A large share of domains that publish DMARC never move past `none`, which means they have the reporting and none of the protection.

## Getting to enforcement

Move `p=none` to `p=quarantine`, wait, then to `p=reject`. Watch the reports at each step and only move when the failures you can see are all mail you do not recognise.

The `t` tag is the modern way to test. `t=y` makes receivers apply `p=none` regardless of what your policy says, so you can publish `p=reject; t=y` and see how enforcement *would* behave without any of the consequences. Remember to remove it. A record reading `p=reject; t=y` protects nothing, and it is the single most common reason somebody is certain they are protected when they are not.

Set `sp` explicitly. It governs subdomains, and if it is weaker than `p`, an attacker simply spoofs `invoices.yourcompany.com` instead. That looks just as convincing in an inbox.

## Reporting, and why it silently fails

Aggregate reports are XML, sent daily, and defined in [RFC 9990](https://www.rfc-editor.org/rfc/rfc9990). They tell you which IPs sent as you and whether each passed.

If your `rua` address is at a different domain to the one being reported on, that domain must authorise it. It publishes a TXT record at `yourdomain._report._dmarc.theirdomain` containing `v=DMARC1`. Without that record, receivers drop the reports and nobody is told. It is the most common reason a domain owner says reporting "does not work".

You can read your own reports without signing up to anything: [Bloodwork](/bloodwork) parses them in your browser and never uploads them.

## Check yours

[Test your DMARC record](/lab/dmarc-checker), including the policy actually being applied if it is inherited from a parent domain. Then ask the blunt question: [can somebody send as you right now](/lab/spoofability). If you are starting from nothing, the [DMARC generator](/lab/dmarc-generator) writes a first record you can paste.
