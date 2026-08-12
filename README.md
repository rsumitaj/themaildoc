# The MailDoc

**The doctor for your domain's email.** Enter a domain, get a full diagnosis of
SPF, DKIM, DMARC, MX, DNSSEC, MTA-STS, TLS-RPT, BIMI, CAA and reverse DNS, a
0 to 100 Vitals score, and every finding with a copy-paste fix and the RFC
section it comes from.

Free, no signup, nothing stored. Runs entirely on Cloudflare's free tier.

## What is in here

| | |
|---|---|
| **The checkup** | Every record at once, scored, triaged, each condition with a prescription |
| **The Lab** | 20 single-purpose tools: SPF, DMARC, DKIM, MX, DNSSEC, reverse DNS, MTA-STS, TLS-RPT, BIMI, CAA, DNS lookup, spoofability, sender readiness, SPF flattener, and four record generators |
| **Bloodwork** | DMARC aggregate report analyser. Decompresses, parses and scores reports entirely in the browser. Files are never uploaded |
| **Checks library** | A page per condition, 159 of them, generated from the catalog |

## Why it is different

**Every finding cites its specification.** Not "your SPF looks wrong" but
`RFC 7208 §4.6.4` with the sentence that rule comes from. The engines are unit
tested against recorded DNS responses so accuracy is provable rather than
asserted.

**The score is reproducible.** Open "How this score works" on any result and it
shows that domain's exact arithmetic, computed by the same function that
produced the number. A test asserts the two can never disagree.

**It says what it cannot know.** Bulk sender requirements that are invisible
from DNS are marked "not checkable" and excluded from the count, rather than
shown as green ticks nobody earned.

## Stack

Astro with Preact islands, deployed to Cloudflare Workers. Prerendered pages are
served as free Worker assets; only `/api/*` consumes invocations. pnpm and
Turborepo, TypeScript project references, Vitest. D1 holds consultation
requests and nothing else.

```
apps/
  web/                  Astro site, API endpoints, islands
packages/
  shared/               vocabulary, domain normalisation, limits
  catalog/              every condition: severity, wording, prescription, RFC
  resolver/             DNS-over-HTTPS client, two providers, agreement checks
  engines/              RFC analysis. Pure, framework free, no I/O of its own
  report-parsers/       DMARC aggregate reports. Browser only, never the server
  ui/                   design tokens and components
  geo/                  IP to country, phase 2
```

`catalog`, `resolver` and `engines` are framework free, so accuracy is provable
in CI against mock DNS fixtures, and the same core could back a CLI later
without a rewrite.

## Working on it

```bash
pnpm install
pnpm dev         # http://localhost:4321
pnpm test        # 524 tests across every package
pnpm typecheck   # whole-repo tsc plus astro check
pnpm build
```

Preview the real Worker, static assets and `/api/*` exactly as Cloudflare runs
them:

```bash
pnpm build
cd apps/web && npx wrangler dev
```

Always check the production build before shipping. The dev server and the built
Worker have diverged on this project before, and only the build caught it.

## The API

| Endpoint | Does |
|---|---|
| `GET POST /api/check?domain=` | the full checkup, Vitals and spoofability |
| `GET POST /api/check/dkim?domain=&selector=` | DKIM selector discovery and key strength |
| `GET POST /api/lookup?domain=&type=` | raw DNS records with TTLs, read through two resolvers |
| `GET POST /api/flatten?domain=` | SPF flattening with the staleness caveat |
| `POST /api/consult` | consultation requests, the only endpoint that writes |

Every read endpoint caches briefly, rate limits per IP, and returns
`{ ok: false, error: { code, message } }` on failure. None of them store
anything.

## Documentation

| | |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | request lifecycle, package rules, the 50-subrequest and 10ms limits, the judgement calls the engines encode |
| [`docs/SCORING.md`](docs/SCORING.md) | the Vitals model in full, including every deviation from the plain additive score and why |
| [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md) | voice, code and design rules, and the lint that enforces them |
| [`docs/DEPLOY.md`](docs/DEPLOY.md) | Cloudflare setup, D1, WAF rate limits, headers, going live |

## Fonts

Space Grotesk and JetBrains Mono, self-hosted from `apps/web/public/fonts/`
under the SIL Open Font License 1.1. No third-party font CDN.

## Licence

All rights reserved. The tools are free to use at
[themaildoc.co](https://themaildoc.co); the source is not licensed for reuse.
