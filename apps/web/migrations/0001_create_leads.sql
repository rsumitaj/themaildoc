-- Consultation requests.
--
-- One row per person who asked for help, with the clinical context they were
-- looking at when they asked. The columns are deliberately explicit rather than
-- a JSON blob: this table is read by a human deciding who to answer first, and
-- "which failing domains asked for help this week" has to be one query.
--
-- Apply with:
--   wrangler d1 execute maildoc-leads --remote --file=migrations/0001_create_leads.sql

CREATE TABLE IF NOT EXISTS leads (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),

  -- Who they are
  name          TEXT    NOT NULL,
  email         TEXT    NOT NULL,
  company       TEXT,

  -- What they need
  domain        TEXT,
  help_with     TEXT    NOT NULL,   -- dmarc | deliverability | spoofing | spf | audit | other
  message       TEXT,

  -- The clinical context, so the first reply can be specific
  vitals_score  INTEGER,            -- 0-100 at the moment they asked, if known
  vitals_band   TEXT,               -- HEALTHY | NEEDS_CARE | AT_RISK | CRITICAL
  spoofable     TEXT,               -- SPOOFABLE | PARTIAL | PROTECTED

  -- Where it came from
  source_page   TEXT,
  referrer      TEXT,
  country       TEXT,               -- Cloudflare's request.cf.country
  user_agent    TEXT,

  -- Triage
  status        TEXT    NOT NULL DEFAULT 'new'   -- new | contacted | won | closed
);

-- Newest first is the only listing anyone wants.
CREATE INDEX IF NOT EXISTS idx_leads_created  ON leads (created_at DESC);
-- Working the queue.
CREATE INDEX IF NOT EXISTS idx_leads_status   ON leads (status, created_at DESC);
-- The same person asking twice is one relationship, not two.
CREATE INDEX IF NOT EXISTS idx_leads_email    ON leads (email);
-- "Who asked about a domain in critical condition" — the highest-intent slice.
CREATE INDEX IF NOT EXISTS idx_leads_domain   ON leads (domain);
