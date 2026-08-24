# Architecture

How a diagnosis actually happens, and why each piece is where it is.

## Request lifecycle

```
Browser (static HTML, no JS until the patient types)
   ├─ POST /api/check ──────► Worker
   │                            healthCheck orchestrator
   │                              ├─ DohResolver ── Google → Cloudflare (agreement)
   │                              ├─ engines: spf · dmarc · mx · a · dnssec
   │                              ├─ spoofability (derived, no extra queries)
   │                              └─ Cache API: DoH ≤300s · result 60s
   ├─ POST /api/check/dkim ─► Worker: selector probe (own subrequest budget)
   ├─ POST /api/check/spf ──► Worker: the whole include chain, to the end
   ├─ GET  /api/spf/ip ─────► Worker: check_host() for one address
   │
   │   finalizeCheckup(core, deepSpf, dkim) in the browser
   │     one merge, one score, one verdict, read by every consumer
   │
   ├─ POST /api/checkup/score ► Worker: corrects the recorded row to what was read
   └─ RUA / EML files ──────► parsed in the browser. They never reach us.
```

## Why the packages are split this way

| Package | Rule it obeys |
|---|---|
| `shared` | vocabulary and limits only — no I/O, no framework |
| `catalog` | the only place patient-facing wording exists. Engines emit codes, never sentences |
| `resolver` | the only place that talks to the network |
| `engines` | pure analysis over resolver results. No DOM, no Astro, no fetch |
| `ui` | design tokens + primitives. No product logic |
| `report-parsers` | **browser only.** Reports are the patient's data — no `fetch`, no server import path, no dependency on any package that has one |
| `geo` | phase 2; reads GeoLite2 out of R2 |
| `apps/web` | thin. Pages, islands, endpoints — no RFC logic |

`catalog + resolver + engines` are framework-free so accuracy is provable in CI
against mock DoH fixtures, and so the same core can back a CLI or a paid
monitoring tier later without a rewrite.

## The two hard limits everything is designed around

**50 subrequests per Worker request.** The orchestrator hands each engine a slice
of a shared budget and every engine reports partial results honestly rather than
guessing when it runs out. DKIM's selector probe is a separate endpoint because
13 speculative lookups would not fit beside SPF's chain walk.

**10 ms CPU per request.** DoH is I/O, so this is comfortable — but it rules out
anything cryptographic in bulk. DKIM key parsing uses WebCrypto with a cheap DER
fallback.

## Judgement rules the engines encode

**PTR is only asserted for servers the domain actually owns.** Reverse-DNS
findings apply to MX hosts inside the domain's own zone, plus apex addresses
when its SPF contains a bare `a`. A domain on Google Workspace publishes
Google's MX — telling that customer to fix Google's PTR would be wrong and
impossible to act on. Vendor ranges reached through an SPF `include:` are never
judged.

**BIMI is not an RFC.** It is `draft-brand-indicators-for-message-identification`.
Citing an RFC number for it, as several checkers do, is the kind of detail that
decides whether the rest of our citations are believed.

**The MTA-STS policy fetch must not follow redirects** (RFC 8461 §3.3), so it
uses `redirect: 'manual'`. A certificate failure surfaces as unreachable,
because that is exactly what a sending server would conclude.

**Optional hardening cannot outweigh authentication.** MTA-STS, TLS-RPT, BIMI,
CAA and DNSSEC live in their own pillar, worth 15 of the 100, so no amount of
missing hardening can drag a domain with correct SPF, DKIM and an enforcing
DMARC policy down beside one with no email setup at all. The deduction caps
that used to do this job are gone; the pillars do it structurally. See
[SCORING.md](SCORING.md).

**Absence is not the same as a fault.** Every finding is a fault in something
published, so a domain that publishes nothing collects almost no findings. Three
absences — no zone at all, no DMARC record, no SPF record — cap the pillars they
serve rather than merely charging them, because a missing record is not a
tidiness problem with the record.

**Score once per problem.** `scoreBreakdown` charges each distinct code a
single time however often it was found — three DKIM selectors with 1024-bit
keys is one fix, and charging it three times reported a well-run domain as
being in critical condition over a tidy-up.

**A report is not a configuration.** Bloodwork findings (`record: 'RUA'`) are
skipped by `scoreBreakdown` outright. Vitals score what a domain publishes
today; an aggregate report describes what its mail did last week, and letting a
quiet week move the number would flatter a broken domain.

## Bloodwork: reading a report you did not write

**Two verdicts live in every aggregate report and they are not the same.**
`policy_evaluated` is the receiver's own summary and is already alignment-aware
(RFC 9990 §3.1.1) — ground truth for what happened to the mail. `auth_results`
is the evidence behind it. We recompute alignment from the evidence (RFC 9989
§4.4) and show both, because a receiver routinely records a pass for forwarded
mail on the strength of the *forwarder's* SPF, which authenticates nobody. On
the sample report that is the difference between 97.5% and 96.6%.

**The organisational domain comes from the report, not a PSL.** DMARCbis
replaced the Public Suffix List with a DNS tree walk (§4.10), which needs
queries a browser-side parser must not make. The report already answers it: the
policy was discovered at `policy_published.domain`, so that is the
organisational domain for everything the report covers.

**The XML reader has no DTD support and expands no entities.** RFC 9990 §8.1
says report content is an attack surface; an `&xxe;` stays five literal
characters, and a file that declares entities is refused with that sentence.

**Forwarded and forged look alike.** An attacker who copies a DKIM-Signature
header produces the same shape as a mailing list that broke one. The classifier
puts proof of alignment above everything, forwarding evidence above the
reporter's own verdict, and the UI states the ambiguity rather than hiding it.

## Accuracy rules that are not negotiable

- Two resolvers must agree before a verdict depends on the answer; disagreement
  becomes `PROPAGATION_IN_PROGRESS`, never a confident wrong answer.
- Our own network failure is never reported as the patient's misconfiguration
  (a timeout is `RESOLVER_TIMEOUT`, not "record missing"; a SERVFAIL during EDV
  is "unverified", not "unauthorized").
- Google's DoH concatenates multi-string TXT records and drops the quotes.
  Segmentation-dependent checks only run on data from a resolver that preserves
  them — see `TxtRecord.segmented`.
- A void lookup is NXDOMAIN or NOERROR-with-no-records (RFC 7208 §4.6.4), and a
  lookup we never completed is not void.

## Build traps that cost real time (do not re-learn these)

**The dev server can be green while the build is broken.** `@astrojs/cloudflare`
14.2.1 prerenders inside workerd by default, and that path wrote the literal
string `[object Object]` into every static HTML file. `astro dev` was perfect
throughout. We now set `prerenderEnvironment: 'node'` in the adapter options.
Any time the adapter or Astro is upgraded, check a built page:

```bash
pnpm build && head -c 80 apps/web/dist/client/index.html
```

**Stale `dist/` silently wins.** Workspace packages publish `exports` pointing
at `dist/`, so anything resolving through node_modules gets the *last build*,
not your edit. That surfaces as impossible behaviour — missing catalog codes, a
score that will not change. Both consumers are pinned to source instead:
`vitest.config.ts` at the root (projects + aliases) and `vite.resolve.alias` in
`astro.config.mjs`.

**Stale `dist/` also fools the type checker.** `astro check` resolves
`@maildoc/*` through each package's built `.d.ts` unless told otherwise, so a
real type error can look like a phantom. `apps/web/tsconfig.json` carries
`paths` pointing at source, matching the Vite aliases.

**The Worker is served from the adapter's generated config**, not the checked-in
one: `wrangler dev -c dist/server/wrangler.json`. Running plain `wrangler dev`
against `apps/web/wrangler.jsonc` serves the site without its assets.

## Response shape

`/api/check` returns `{ domain, vitals, records[], conditions[], spoofability,
detail, meta }`. `conditions[]` is already triaged, interpolated and weighted by
the catalog; the client renders, it never decides severity.

Two checks have endpoints of their own, for the same reason: a Worker gets fifty
subrequests and neither fits inside the checkup's share. `/api/check/dkim`
probes speculative selectors. `/api/check/spf` walks the include chain to the
end, spending `SPF_DEEP_WALK_BUDGET` on nothing else, and is authoritative over
the bounded chain the checkup itself walks. The result screen fires all three
together.

`/api/spf/ip` is not one of those legs and never joins the merge. It answers a
different question — whether one address may send as the domain — and its answer
is a fact about a sender rather than about the domain's health. A perfectly
configured domain returns `fail` for every address it does not authorise, so
letting it near Vitals would score domains down for working correctly. It
records the domain as examined and writes no score.

`finalizeCheckup` in `engines/src/finalize.ts` is the one place those three legs
are merged, and every consumer reads its result rather than merging for itself.
That rule is the whole point of the file. When it did not exist, the result
screen merged correctly, `/api/check` recorded a score with no DKIM in it, the
readiness page read an SPF chain the deep walk had already superseded, the spoof
banner kept the bounded walk's reasons, and "partial result" stayed on screen
after the walk that completed it had landed. A fourth leg added later means
changing that file and nothing else.

Because both later legs can only *add* findings, the score `/api/check` records
is an over-estimate of health by construction. `/api/checkup/score` is how the
finished number gets back: it updates an existing row, never inserts, never
touches `checks`, and enum-checks its input. It is the only value in either
table that arrives from a page rather than from an engine, which is why it is
the most tightly bounded write in the codebase. See `docs/DEPLOY.md` for what
provisional and final rows mean when reading the table.
