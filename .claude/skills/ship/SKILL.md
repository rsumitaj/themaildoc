---
name: ship
description: The pre-deploy gate for themaildoc.co — run the full verification chain (tests, typecheck, build, budgets, live smoke) before anything goes to Cloudflare. Use when asked to ship, deploy, release, or confirm the site is production-ready.
---

# Ship

Run in order. Every step must pass; none may be skipped because it "obviously" still works.

```bash
pnpm test        # every package — engines are the product
pnpm typecheck   # tsc across src+tests, then astro check
pnpm build       # tsc -b for packages, astro build for the site
```

Then the checks a green build does not catch:

1. **Live smoke** — run the diagnosis against `google.com`, `github.com`,
   `cloudflare.com`, `nasa.gov` and a domain with no SPF at all. Compare lookup
   counts and policies against what the record actually says. A number that
   disagrees with the published record is a release blocker.
2. **Budget** — confirm no single `/api/*` request can exceed 50 subrequests.
3. **Escaping** — confirm no DNS-derived string reaches the DOM unescaped.
4. **Emoji** — none in production output. Match `\p{Extended_Pictographic}` but exclude
   `©®™` and other typographic signs, which that property includes and which are not emoji.
5. **Mobile** — 390px wide: `document.documentElement.scrollWidth === innerWidth`.
6. **Meta** — every new page has a unique title, description, canonical, and its
   JSON-LD validates.

Deploy is `pnpm --filter @maildoc/web deploy` (astro build + wrangler deploy).
It needs Cloudflare credentials, so ask before running it — never deploy
unprompted.
