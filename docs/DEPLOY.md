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

Add to `wrangler.jsonc` once the zone exists in the same Cloudflare account:

```jsonc
"routes": [
  { "pattern": "themaildoc.co", "custom_domain": true },
  { "pattern": "www.themaildoc.co", "custom_domain": true }
]
```

Cloudflare creates the DNS records itself. Redeploy after adding them.

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
| Consultations | `http.request.uri.path eq "/api/consult"` | 5 per hour per IP | Block, 1h |

The flattener gets its own rule because it is the most expensive thing here:
one request walks a whole include chain and resolves every host inside it.

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

The domain has to pass its own checkup before launch. At minimum: SPF with a
hard fail, DKIM on whatever sends, `p=reject` DMARC with a `rua` address, and
MTA-STS. Anyone evaluating this site will check the domain it runs on first.

## Reading the leads

```bash
pnpm --filter @maildoc/web leads       # last 50
pnpm --filter @maildoc/web leads:new   # unanswered only
```
