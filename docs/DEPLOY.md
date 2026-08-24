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
pnpm db:migrate:checkups                 # creates the checkups table remotely
pnpm db:migrate:score                    # adds score_complete to it
pnpm ship                                # builds and pushes
```

## The two tables

`leads` is consultation requests: a name, an address and what they asked for.
Written only by `/api/consult`, only when somebody submits the form.

`checkups` is one row per domain examined, with the score it got and the date.
Written by `/api/check`, `/api/lookup`, `/api/flatten` and `/api/bimi`. It holds
nothing identifying a person, no address and no session, and rows are deleted 90
days after the domain was last checked. `/privacy` states all of that, and the
two have to change together: the page is the disclosure that makes the table
legitimate.

```bash
pnpm checkups        # worst score first, the working order
pnpm checkups:hot    # spoofable or under 40, the ones worth a conversation
pnpm domains         # live tail, as checks happen
```

### Provisional and final scores

The `score` column those two queries print is `score_complete`, and it is the
difference between a number worth acting on and a number worth checking.

A checkup is three requests, because fifty subrequests is not enough for one.
`/api/check` reads nine records and writes the row. The DKIM selector probe and
the full include-chain walk land afterwards, in the browser, and both can only
*add* findings. So the score the endpoint writes is never worse than the truth,
and for a while it was the only score this table ever held: rows sat at 85 and
HEALTHY under result screens reading 78 and NEEDS CARE.

The result screen now posts the finished number back to `/api/checkup/score`,
which updates the row and marks it `final`. A row still marked `provisional`
means no screen ever reported: the visitor closed the tab, ran without
JavaScript, or one of the two later legs failed. Read its score as *no worse
than this*, and re-run the checkup if it matters.

That endpoint updates and never inserts, never touches `checks`, and range- and
enum-checks everything before it reaches SQL, because it is the one value in
either table that arrives from a page rather than from an engine.

Pruning is opportunistic: every hundredth write deletes anything past the
window. There is no cron trigger, because the static adapter gives no scheduled
handler to hang one on. If traffic ever stops for months, run the delete by
hand:

```bash
pnpm --filter @maildoc/web exec wrangler d1 execute maildoc-leads --remote \
  --command "DELETE FROM checkups WHERE last_seen < date('now','-90 days');"
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
