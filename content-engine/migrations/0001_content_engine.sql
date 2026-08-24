-- MailDoc Content Engine tables. Prefixed ce_ so they sit cleanly beside the
-- site's `leads` and `checkups` in the same maildoc-leads database.

-- One row per pipeline run (cron or manual), for observability + weekly counts.
CREATE TABLE IF NOT EXISTS ce_run (
  id            TEXT PRIMARY KEY,
  started_at    TEXT NOT NULL,
  finished_at   TEXT,
  trigger       TEXT NOT NULL,               -- 'cron' | 'manual'
  status        TEXT NOT NULL DEFAULT 'running', -- running|ok|skipped|error
  iso_week      TEXT NOT NULL,               -- e.g. 2026-W35, for volume caps
  note          TEXT,
  stats_json    TEXT
);

-- Scored topic candidates. Kept even when rejected, so selection is auditable
-- and the same topic is never reconsidered blindly.
CREATE TABLE IF NOT EXISTS ce_candidate (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL,
  kind          TEXT NOT NULL,               -- 'trendy' | 'news'
  source        TEXT NOT NULL,               -- gsc|rss:<feed>|trends
  title         TEXT NOT NULL,
  keyword       TEXT,
  ref_url       TEXT,                        -- source article, if any
  score         INTEGER,
  scores_json   TEXT,                        -- per-check breakdown
  verdict       TEXT,                        -- 'selected'|'rejected'|'below_threshold'
  reason        TEXT,
  created_at    TEXT NOT NULL
);

-- A generated, checked draft awaiting your decision.
CREATE TABLE IF NOT EXISTS ce_draft (
  id              TEXT PRIMARY KEY,
  candidate_id    TEXT,
  kind            TEXT NOT NULL,
  slug            TEXT NOT NULL,
  title           TEXT NOT NULL,
  keyword         TEXT NOT NULL,
  frontmatter_json TEXT NOT NULL,            -- the exact Zod-shaped frontmatter
  body_md         TEXT NOT NULL,
  word_count      INTEGER NOT NULL,
  content_score   INTEGER,
  checks_json     TEXT,                      -- every content check + pass/score
  status          TEXT NOT NULL DEFAULT 'draft', -- draft|emailed|published|discarded|expired
  preview_secret  TEXT NOT NULL,             -- unguessable preview URL segment
  commit_sha      TEXT,
  created_at      TEXT NOT NULL,
  updated_at      TEXT NOT NULL
);

-- Single-use, expiring approval tokens (publish / discard). We store only a
-- hash of the token; the token itself lives only in the email link.
CREATE TABLE IF NOT EXISTS ce_approval (
  id            TEXT PRIMARY KEY,
  draft_id      TEXT NOT NULL,
  action        TEXT NOT NULL,               -- 'publish' | 'discard'
  token_hash    TEXT NOT NULL,
  expires_at    TEXT NOT NULL,
  used_at       TEXT,
  created_at    TEXT NOT NULL
);

-- Dedup memory: slugs, news article ids, normalised topics we've already seen.
CREATE TABLE IF NOT EXISTS ce_seen (
  key           TEXT PRIMARY KEY,            -- e.g. 'slug:spf-permerror-explained'
  kind          TEXT NOT NULL,
  first_seen    TEXT NOT NULL
);

-- Search Console mirror, refreshed by scripts/gsc-sync.mjs or the measure step.
-- This is what makes topic selection data-driven per page + query.
CREATE TABLE IF NOT EXISTS ce_gsc_query (
  snapshot_date TEXT NOT NULL,
  query         TEXT NOT NULL,
  clicks        INTEGER NOT NULL DEFAULT 0,
  impressions   INTEGER NOT NULL DEFAULT 0,
  position      REAL,
  ctr           REAL,
  PRIMARY KEY (snapshot_date, query)
);

CREATE TABLE IF NOT EXISTS ce_gsc_page (
  snapshot_date TEXT NOT NULL,
  page          TEXT NOT NULL,
  clicks        INTEGER NOT NULL DEFAULT 0,
  impressions   INTEGER NOT NULL DEFAULT 0,
  position      REAL,
  PRIMARY KEY (snapshot_date, page)
);

CREATE INDEX IF NOT EXISTS idx_draft_status ON ce_draft (status);
CREATE INDEX IF NOT EXISTS idx_candidate_run ON ce_candidate (run_id);
CREATE INDEX IF NOT EXISTS idx_gscq_impr ON ce_gsc_query (snapshot_date, impressions);
