# MailDoc Content Engine

An isolated Cloudflare Worker that researches trending email-security topics,
drafts RFC-accurate articles in the MailDoc voice, runs stacked quality checks,
and — only when you tap **Publish** in an email — commits the finished post into
`apps/web/src/content/library/`, where the normal site build ships it.

Two posts a week of trendy/searched topics plus one on that week's email-security
news, all configurable. If nothing clears the bar in a given week, it posts
nothing. Nothing is ever published without your click.

- Runs on the same D1 as the site (`maildoc-leads`), adding `ce_*` tables.
- One free Gemini key drives every AI step. No paid services anywhere.
- Deployed separately from the site Worker; it cannot break the site build.

## Pipeline

`cron -> select (8 checks) -> write (10+ checks + critique) -> draft in D1 ->
email you -> [you tap Publish] -> commit to repo -> site deploys -> IndexNow`

See `src/skills/*.md` for the agent briefs and `src/prompts.ts` for the live
prompts.

## Secrets (set with `wrangler secret put NAME`)

| Secret | For | Where |
|---|---|---|
| `GEMINI_API_KEY` | drafting + all AI checks | Google AI Studio (free) |
| `GITHUB_TOKEN` | commit the published post | GitHub fine-grained PAT, Contents: R/W on this repo |
| `GSC_SA_EMAIL` + `GSC_SA_PRIVATE_KEY` | read Search Console demand | Google Cloud service account added to the GSC property |
| `RESEND_API_KEY` | send the approval email | resend.com (free tier) |
| `APPROVAL_EMAIL` | where approvals go — **you fill this** | your inbox |
| `APPROVAL_SIGNING_SECRET` | sign one-tap publish tokens | any long random string |
| `RUN_TOKEN` | guard the manual `/run` endpoint | any random string |
| `DEVTO_API_KEY` | (optional) syndication | dev.to |

## Config (edit `wrangler.jsonc` `vars` — no code change)

| Var | Default | Meaning |
|---|---|---|
| `WEEKLY_TRENDY_POSTS` | `2` | trendy/searched posts per ISO week |
| `WEEKLY_NEWS_POSTS` | `1` | news-driven posts per ISO week |
| `MIN_TOPIC_SCORE` | `68` | below this, a topic is not written |
| `MIN_CONTENT_SCORE` | `80` | below this, a draft is held, not emailed |
| `MAX_REGEN_ATTEMPTS` | `3` | rewrite tries before holding a draft |
| `TARGET_WORDS_MIN/MAX` | `850`/`1600` | article length band |
| `APPROVAL_TTL_HOURS` | `120` | how long a publish link stays valid |
| `GEMINI_MODEL` | `gemini-2.5-flash` | any current free-tier Gemini model |
| `GITHUB_REPO` | `OWNER/themaildoc` | set to your repo |
| `DRY_RUN` | `false` | `true` = run everything but do not send email |

**Change the volume** by editing `WEEKLY_TRENDY_POSTS` / `WEEKLY_NEWS_POSTS` and
redeploying. The cron runs daily; the code produces only the remaining slots for
the current week, so the schedule never changes.

## Setup

```bash
cd content-engine
npm install
cp .dev.vars.example .dev.vars   # fill it in for local dev

# 1. Create the tables in the shared D1
npm run migrate:remote

# 2. Set each production secret
npx wrangler secret put GEMINI_API_KEY
# ...repeat for every secret in the table above

# 3. Point it at your repo: edit GITHUB_REPO in wrangler.jsonc

# 4. Deploy
npm run deploy
# note the workers.dev URL it prints, then set it so email links work:
npx wrangler secret put ENGINE_PUBLIC_URL   # e.g. https://maildoc-content-engine.<sub>.workers.dev

# 5. Warm the database with real GSC data (optional but recommended)
npm run gsc:sync
npx wrangler d1 execute maildoc-leads --remote --file=data/gsc-seed.sql

# 6. Test end to end without waiting for cron (DRY_RUN or real):
curl -H "Authorization: Bearer $RUN_TOKEN" https://<engine-url>/run
```

## Publishing + deploy

`Publish` commits the post to `CONTENT_DIR` on `GITHUB_BRANCH`. Your site must
rebuild for it to go live. Either:
- enable **Cloudflare Workers Builds** (git integration) on the site, or
- add the included `deploy-content.yml.example` to `.github/workflows/` (set
  `CLOUDFLARE_API_TOKEN` + `CLOUDFLARE_ACCOUNT_ID` as repo secrets). It builds,
  deploys, and runs `pnpm indexnow` on every content push.

## Failure modes (handled)

| Case | Behaviour |
|---|---|
| No topic clears `MIN_TOPIC_SCORE` | Run ends `skipped`; nothing emailed. Silence is valid. |
| Weekly target already met | Run ends `skipped` before any AI call. |
| Draft fails a hard check (em dash, schema, brand) | Regenerate with the exact failure fed back, up to `MAX_REGEN_ATTEMPTS`; then held, not emailed. |
| Draft below `MIN_CONTENT_SCORE` after retries | Held as `draft`; you are not emailed junk. |
| Gemini 429 / 5xx / timeout | Retried with backoff; a whole-run failure ends the run `error` and is logged in `ce_run`. |
| GSC API down | Caught; selection falls back to news + evergreen judgement. |
| Email send fails | Draft stays `draft`; logged; retried next run. |
| Publish link reused | Refused (single-use); no double publish. |
| Publish link expired / tampered | Refused with a clear message. |
| GitHub commit conflict | Uses the existing file sha to update in place; errors are returned, draft kept safe. |
| Duplicate topic | Deduped against live slugs (sitemap) and `ce_seen` before writing. |
| Two cron runs overlap | Weekly counts + `ce_seen` make re-runs idempotent per week. |

## Cost

Gemini free tier, Cloudflare Workers/D1/Cron free tier, Resend free tier, GitHub
free. At 2-3 posts/week you stay far inside every allowance. ~$0/month.

## Local dev

```bash
npm run dev            # wrangler dev; hit http://localhost:8787/health
# trigger a scheduled run locally:
curl "http://localhost:8787/run?token=$RUN_TOKEN"
```
Set `DRY_RUN=true` in `.dev.vars` to exercise the whole pipeline without sending
email — drafts still land in D1 and are viewable at `/preview/<secret>`.
