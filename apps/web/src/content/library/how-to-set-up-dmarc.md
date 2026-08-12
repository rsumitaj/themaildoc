---
title: "How to Set Up DMARC: A Step by Step Guide"
description: "Set up DMARC from nothing: the first record to publish, where it goes, what to watch in the reports, and how to reach enforcement safely."
keyword: "how to set up DMARC"
heading: "How to set up DMARC"
standfirst: "From no record to enforcement, in five steps. The first takes ten minutes; the rest are mostly waiting and reading."
kind: cluster
pillar: dmarc-guide
updated: 2026-08-13
published: 2026-08-13
tools: ["dmarc-generator", "dmarc-checker", "dmarc-report-analyzer", "spoofability"]
related: ["dmarc-guide", "p-none-vs-quarantine-vs-reject", "what-is-dmarc"]
steps:
  - name: "Get SPF and DKIM working first"
    text: "DMARC decides what to do when both fail, so it has nothing to work with until at least one of them passes for your domain. Check both before publishing anything."
  - name: "Publish p=none with a reporting address"
    text: "Add a TXT record at _dmarc.yourdomain containing v=DMARC1; p=none; rua=mailto:dmarc@yourdomain. This changes nothing about how your mail is handled and turns reporting on."
  - name: "Wait for a full billing cycle and read the reports"
    text: "Two to four weeks. You are waiting for the monthly invoice run and the quarterly newsletter to appear, so that the list of systems sending as you is complete."
  - name: "Authorise every sender you recognise"
    text: "For each source in the reports that is genuinely yours, either add it to SPF or have it sign with a DKIM key published in your DNS. Leave the rest failing."
  - name: "Move to quarantine, then reject"
    text: "When the only failures left are mail you do not recognise, raise the policy. Wait between each step and keep reading the reports."
faq:
  - q: "Do I need SPF and DKIM before DMARC?"
    a: "You need at least one of them passing and aligned with your domain. DMARC only asks whether SPF or DKIM passed for the From domain, so with neither working, publishing p=reject would refuse your own mail."
  - q: "Where exactly does the DMARC record go?"
    a: "A TXT record at _dmarc.yourdomain.com. Not at the domain itself, and not at dmarc.yourdomain.com. Most DNS panels want the host field as _dmarc and add the rest for you."
  - q: "What email address should reports go to?"
    a: "A mailbox you will actually open, or a service that parses them. The files are XML and unreadable by eye at volume. If the address is at a different domain, that domain has to authorise it with its own record."
  - q: "How long does DMARC take to work?"
    a: "The record is live within minutes. The first aggregate reports arrive within about 24 hours, and a useful picture takes two to four weeks because you are waiting for your own less frequent sending to show up."
---

Five steps. The first takes ten minutes and the rest are mostly waiting.

## 1. Get SPF and DKIM working first

DMARC passes when SPF or DKIM passes **and** aligns with your From domain. With neither working, publishing `p=reject` would refuse your own mail.

Check both before you publish anything: [SPF](/lab/spf-checker) and [DKIM](/lab/dkim-checker). Two things in particular. Is SPF under the ten lookup limit? Does DKIM sign with a key published at your domain rather than your provider's?

## 2. Publish the first record

A TXT record at `_dmarc.yourcompany.com`:

```
v=DMARC1; p=none; rua=mailto:dmarc@yourcompany.com
```

That is it. `p=none` changes nothing about how your mail is handled, so this cannot break anything. It turns reporting on.

Two details people get wrong. The record goes at `_dmarc.yourcompany.com`, not at the domain itself. And if your `rua` address is at a *different* domain, that domain must publish a TXT record at `yourcompany.com._report._dmarc.theirdomain.com` containing `v=DMARC1`, or receivers drop the reports silently. That rule is in [RFC 9990 section 4](https://www.rfc-editor.org/rfc/rfc9990#section-4).

[The DMARC generator](/lab/dmarc-generator) writes the record for you if you would rather not hand-assemble it.

## 3. Wait, and read the reports

The first reports arrive within a day. A useful picture takes two to four weeks, because you are waiting for your own infrequent sending to appear: the monthly invoice run, the quarterly newsletter, the annual renewal notice.

Aggregate reports are gzipped XML and unreadable by eye at any volume. [Bloodwork](/bloodwork) parses them in your browser, without uploading them anywhere.

## 4. Authorise what is yours

The reports will list sources you did not expect. A CRM somebody trialled, a ticketing system, a payroll provider, a script on a server under a desk.

For each one, decide whether it is yours. If it is, authorise it: add it to SPF, or get it signing with a DKIM key published in your DNS. DKIM is the better answer where you have the choice, because it survives forwarding and does not spend one of your ten lookups.

If it is not yours, leave it failing. That is the mail you are about to start blocking, and seeing it in a report is the point of the whole exercise.

## 5. Raise the policy

When the only failures left are mail you do not recognise, move to `p=quarantine`. Wait again, read again, then `p=reject`.

Set `sp` explicitly at every step. It governs subdomains, and if it is weaker than `p`, an attacker spoofs `invoices.yourcompany.com` instead.

## Confirm it worked

[Check the record](/lab/dmarc-checker) to see the policy receivers actually apply, then ask the direct question: [can somebody still send as you](/lab/spoofability).
