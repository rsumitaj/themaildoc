# The Vitals score

One page, because a number nobody can reproduce is a number nobody should
trust. Everything here is implemented in `packages/catalog/src/score.ts` and
asserted in `packages/catalog/test/score.test.ts`. If this document and that
file ever disagree, the file is right and this is a bug.

## Four questions, not one list

The score is not one pool that every finding subtracts from. It is four
questions, each answered out of 100, then weighted:

| Pillar | Weight | The question it answers |
|---|---|---|
| Impersonation defence | 45 | Can somebody send mail that looks like it came from you? |
| Delivery integrity | 25 | Will the mail you really send arrive? |
| Visibility | 15 | Would you find out if either went wrong? |
| Hardening | 15 | Optional protections no receiver requires but good senders publish |

One pool was the original design and it produced answers that were plainly
wrong. A domain publishing `p=reject` scored 0 out of 100 while the same page
said "Protected, your domain can't be easily spoofed", because four unrelated
findings happened to add past 100 and nobody can be more exposed than zero. A
pillar cannot fall below zero, so one catastrophe no longer drags the whole
number to nothing.

Which pillar a finding belongs to is decided by `pillarFor`, from the record and
the category, with a small table of overrides for the codes that do not follow
the default. SPF and DMARC split by what the finding is *about*: an SPF record
authorising the whole internet is impersonation, an SPF record over the
ten-lookup limit is delivery, and they live in the same TXT string.

## What a finding costs its pillar

| Severity | Triage shown | Subtracts |
|---|---|---|
| CRITICAL | Code Red | 40 |
| HIGH | Urgent | 25 |
| MEDIUM | Needs attention | 15 |
| LOW | Minor | 8 |
| INFO | Note | 2 |

Severity is fixed in the catalog, never computed at runtime, so the same
problem costs the same on every domain. Each distinct **code** is charged once
however many times it was found: three DKIM selectors carrying 1024-bit keys is
one fix, not three. The chart still lists every instance.

## What absence costs

Subtraction alone cannot say *you have nothing*. Every finding is a fault in
something published, so a domain that publishes nothing collects almost no
findings and keeps almost all of its marks. A domain registered minutes ago,
with no SPF, no DMARC, no MX and no address records, scored 100 out of 100 on
visibility — there was no DMARC record for a missing `rua` to be a fault in —
and 64 weighted overall.

So three absences cap the pillars they serve, whatever else is tidy:

| Finding | Caps | To | Why |
|---|---|---|---|
| `DOMAIN_NXDOMAIN` | all four | 0 | The name does not resolve, so there is no zone to score (RFC 8020) |
| `DMARC_RECORD_MISSING` | Impersonation, Visibility | 0 | No instruction to refuse forged mail, and no report is ever sent (RFC 9989 §6.3, §7) |
| `SPF_RECORD_MISSING` | Impersonation | 20 | Nothing states which hosts may send (RFC 7208 §2.1) |
| `SPF_RECORD_MISSING` | Delivery | 40 | No path to the authentication bulk receivers require; DKIM alone can still carry a message |

These are ceilings, not fudges. Each is a statement about what a receiver can
do with the domain, and the explainer beside every result names which one
applied.

## The floor and the ceiling from the verdict

The spoofability verdict is computed from the DMARC policy a receiver will
actually apply, which makes it ground truth for the impersonation question.

**Floor.** Impersonation cannot fall below 55 when the verdict is Protected, or
35 when Partial. Without this, hygiene findings on a domain at `p=reject` were
measuring tidiness and calling it exposure.

**Ceiling.** The total cannot rise above 39 when the verdict is Spoofable, or
64 when Partial. These are the tops of the bands below, so the number and the
words beside it always tell one story.

**Precedence.** The floor outranks an absence ceiling. A domain publishing no
SPF but sitting at `p=reject` with a working signature genuinely cannot be sent
as, and the floor is read from what receivers do rather than from what the
domain failed to publish. The reverse never arises: with no DMARC record the
verdict is always Spoofable, whose floor is zero.

A capped score is flagged as capped in the breakdown, so a page can say the
total was held down rather than silently print the clamp. That distinction
matters: a score that is *only* ever the ceiling would read the same for a
domain that is nearly fine and one that does not exist.

## The bands

| Score | Band | What it means |
|---|---|---|
| 85 to 100 | Healthy | Nothing serious. A few tune-ups at most |
| 65 to 84 | Needs care | Real gaps that are costing you delivery or exposure |
| 40 to 64 | At risk | Serious conditions. Authentication is not doing its job |
| 0 to 39 | Critical | Exposed right now |

## Record status is not the score

A record's dot is `rollupRecord`, and it has three states. Any CRITICAL finding
makes the record critical. Any other finding that costs points makes it need
attention. Only a record with nothing against it but INFO notes is healthy.

LOW used to roll up to healthy, which put a green dot beside "DNSSEC: not
enabled" on a chart that was charging eight points for exactly that. Green is
the strongest thing the interface says. INFO stays green on purpose: a domain
with no BIMI record is not faulty, and colouring that amber would spend the one
colour that means "look at this" on something nobody needs to look at.

## What the score does not include

**Bloodwork findings never move Vitals.** Conditions with `record: 'RUA'` are
skipped by `scoreBreakdown` outright. Vitals scores what a domain publishes
today; an aggregate report describes what its mail did last week, and letting a
quiet week move the number would flatter a broken domain.

**Findings that do not apply are never charged.** A domain that receives no mail
is not marked down for missing MTA-STS, and a domain that authorises no senders
is not marked down for missing BIMI. `readPosture` in `healthCheck.ts` reads the
two statements a domain actually made — a null MX (RFC 7505), and an SPF record
that authorises nothing and ends in `-all` — and narrows the findings to match.

## Where the numbers are computed

One function, `packages/catalog/src/score.ts`, called from four places: the
Worker scores the records it checks, the browser re-scores once DKIM and the
deep SPF chain arrive from their own endpoints, the Lab tools score a single
record, and the explainer renders the same breakdown object the score came
from. There is no second model that can drift from the first, and the arithmetic
on screen reconciles to the headline number by construction rather than by
being kept in step by hand.

## Severities we changed after seeing them on real domains

| Code | Was | Now | Why |
|---|---|---|---|
| `SPF_EXTRA_WHITESPACE` | LOW | INFO | Cosmetic. Every parser tested tolerates it |
| `SPF_LOOKUP_APPROACHING_LIMIT` | HIGH | MEDIUM | A warning about the next change, not a fault in this one. The record works today |
| `DMARC_P_QUARANTINE` | (not in spec) | LOW | Quarantine catches forged mail, it just lands somewhere reachable |
| `DMARC_EDV_MISSING` | CRITICAL always | CRITICAL, or MEDIUM as `_PARTIAL` | Critical means blind. If any reporting address is on the domain itself, reports still arrive and only the third-party copy is lost |

## Codes that are ours, not the catalog spec's

`DMARC_P_QUARANTINE` (LOW) does not appear in `context/03`. Quarantine catches
forged mail and delivers it somewhere a determined recipient can still reach, so
it is a real finding, but weighting it like a genuine gap put well-run domains
next to domains with nothing. Anything else added later belongs in this list.
