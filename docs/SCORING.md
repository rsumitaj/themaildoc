# The Vitals score

One page, because a number nobody can reproduce is a number nobody should
trust. Everything here is implemented in `packages/catalog/src/score.ts` and
asserted in `packages/catalog/test/score.test.ts`.

## The arithmetic

Start at 100. Every condition found subtracts the weight of its severity.
Clamp to 0 and 100.

| Severity | Triage shown | Subtracts |
|---|---|---|
| CRITICAL | Code Red | 40 |
| HIGH | Urgent | 25 |
| MEDIUM | Needs attention | 15 |
| LOW | Minor | 8 |
| INFO | Note | 2 |

The severity of every condition is fixed in the catalog, never computed at
runtime, so the same problem always costs the same on every domain.

## The bands

| Score | Band | What it means |
|---|---|---|
| 85 to 100 | Healthy | Nothing serious. A few tune-ups at most |
| 65 to 84 | Needs care | Real gaps that are costing you delivery or exposure |
| 40 to 64 | At risk | Serious conditions. Authentication is not doing its job |
| 0 to 39 | Critical | Exposed right now |

## Three amendments to the plain additive model

All three are deliberate departures from `context/03`, made after the score
stopped discriminating on real domains. Each is in the code and in the tests.

### 1. Each distinct code is charged once

However many times a problem is found, it is charged once. Three DKIM selectors
carrying 1024-bit keys is one fix, not three, and charging it three times
reported GitHub as being in critical condition over a tidy-up. The chart still
lists every instance.

### 2. Minor findings are capped at 20 points between all of them

LOW is 8 and INFO is 2, which is right for one of them. Six is 48, and that put
a domain enforcing `p=reject` with valid SPF and DKIM into the critical band on
hygiene alone: extra whitespace, a long record, two advisories. Tidiness must
not outweigh whether a domain can be impersonated. `MINOR_DEDUCTION_CAP` is 20.

### 3. Optional hardening is capped at 25 points between all of it

`MTASTS`, `TLSRPT`, `BIMI`, `CAA`, `DNSSEC` and IPv6 gaps together removed 33
points. That put a domain with correct SPF, DKIM and an enforcing DMARC policy
within seven points of a domain with no email setup at all. No receiver
requires any of these records, so between them they may remove at most
`HARDENING_DEDUCTION_CAP`, which is 25. Authentication and delivery problems are
charged in full.

## What the score does not include

**Bloodwork findings never move Vitals.** Conditions with `record: 'RUA'` are
skipped by `scoreConditions` outright. Vitals scores what a domain publishes
today; an aggregate report describes what its mail did last week, and letting a
quiet week move the number would flatter a broken domain.

## Where the numbers are computed

The Worker scores the records it checks. The browser re-scores once DKIM
arrives from its own endpoint, using the same exported function, so there is no
second scoring model that can drift from the first.

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
