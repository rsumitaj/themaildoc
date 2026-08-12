# Deploying The MailDoc

Cloudflare Workers, free tier. Static pages are served as Worker assets and
cost nothing; only `/api/*` consumes invocations.

## First deploy

```bash
cd apps/web
npx wrangler login                       # browser OAuth, once per machine

npx wrangler d1 create maildoc-leads     # copy the database_id it prints
#   paste it over PLACEHOLDER_RUN_WRANGLER_D1_CREATE in wrangler.jsonc

pnpm db:migrate                          # creates the leads table remotely
pnpm ship                                # builds and pushes
```

The deploy prints a `*.workers.dev` URL. Smoke test that before attaching the
domain.

## Attaching themaildoc.co

Done. `wrangler.jsonc` carries both custom domains and Cloudflare maintains
their DNS records itself, so the zone needs no A or CNAME added by hand.

```jsonc
"routes": [
  { "pattern": "themaildoc.co", "custom_domain": true },
  { "pattern": "www.themaildoc.co", "custom_domain": true }
]
```

Use `pnpm ship`, not `pnpm deploy`: the second is a built-in pnpm command for
deploying a workspace package and never reaches the script.

## Rate limiting, the durable control

The per-isolate limiter in `src/lib/api.ts` is a speed bump. Worker isolates
are per-colo and short lived, so a distributed client walks past it. These
rules run **before** the Worker is invoked, which is what actually protects the
DNS resolvers and the database.

Security → WAF → Rate limiting rules:

| Rule | Expression | Limit | Action |
|---|---|---|---|
| API burst | `http.request.uri.path contains "/api/"` | 60 per minute per IP | Managed challenge |
| Flattener | `http.request.uri.path eq "/api/flatten"` | 10 per minute per IP | Block, 60s |
| BIMI | `http.request.uri.path eq "/api/bimi"` | 10 per minute per IP | Block, 60s |
| Consultations | `http.request.uri.path eq "/api/consult"` | 5 per hour per IP | Block, 1h |

The flattener gets its own rule because it is the most expensive thing here:
one request walks a whole include chain and resolves every host inside it.
BIMI gets one for the same reason: it fetches a logo and a certificate from
whatever host the record under test names.

**Not yet applied.** These need zone write access, which the deploy token does
not have, so they are a dashboard step.

## Bot protection

Turnstile on the consultation form is the next control worth adding. It is free
and invisible in managed mode. Until it exists, the form is defended by the
honeypot field, the per-email cap of 3 a day, and the 200 a day ceiling in
`api/consult.ts`.

## Security headers

`public/_headers` carries CSP, HSTS, frame options and the rest. Astro merges
its own cache-control entries with that file at build. After any change to the
scripts or fonts a page loads, re-check the CSP: `connect-src` currently allows
`https://cloudflare-dns.com` for Bloodwork's optional sender lookup and nothing
else.

## Email

Cloudflare Email Routing, free, for `support@themaildoc.co`. Receiving only.
Nothing on the site sends mail.

## Dogfooding

Anyone evaluating this site will check the domain it runs on first, so it has
to pass its own checkup. As of the last deploy it scores **33 and reads
SPOOFABLE**, because there is no DMARC record.

Email Routing is on, so Cloudflare already publishes the MX records and
`v=spf1 include:_spf.mx.cloudflare.net ~all`. Nothing sends as this domain:
Email Routing forwards inbound mail and cannot send, and the SPF record
includes no sending provider. That makes the parked configuration the correct
one.

DNS → Records, one TXT record:

| Type | Name | Content |
|---|---|---|
| TXT | `_dmarc` | `v=DMARC1; p=reject; sp=reject; rua=mailto:dmarc@themaildoc.co` |

Then Email → Routing → add `dmarc@themaildoc.co` forwarding to your inbox, or
the reports have nowhere to land.

Alignment is left relaxed on purpose. Strict would be tighter today and would
have to be loosened the moment a sending provider is added.

If a sender is ever added, its SPF include and DKIM selector go in first, and
`p=reject` only stays once reports show that sender aligning.

Two one-click wins in the same dashboard: DNSSEC (DNS → Settings) and a CAA
record naming your certificate authority.

## Reading the leads

```bash
pnpm --filter @maildoc/web leads       # last 50
pnpm --filter @maildoc/web leads:new   # unanswered only
```
