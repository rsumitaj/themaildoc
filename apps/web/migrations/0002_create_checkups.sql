-- Domains that have been examined here.
--
-- One row per domain rather than one per check. The question this table is
-- read for is "which domains are struggling and worth contacting", and that is
-- a list of domains, not a log of requests. A popular domain checked forty
-- times is one prospect, and storing it forty times would make the table forty
-- times the size while making that question harder to answer.
--
-- Held for 90 days from the last check. A domain examined three months ago is
-- cold, the person who checked it has moved on, and keeping it longer would be
-- storing more than the purpose needs. `prune` in `lib/checkups.ts` does the
-- deleting; `/privacy` states the window.
--
-- Apply with:
--   wrangler d1 execute maildoc-leads --remote --file=migrations/0002_create_checkups.sql

CREATE TABLE IF NOT EXISTS checkups (
  -- The domain is the identity. `ON CONFLICT` folds a repeat check into the
  -- existing row rather than adding one.
  domain        TEXT    PRIMARY KEY,

  first_seen    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  last_seen     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
  checks        INTEGER NOT NULL DEFAULT 1,

  -- The most recent result, so the list can be worked worst first. Null for a
  -- domain that only ever went through a single-record Lab tool, which has no
  -- overall score to give.
  vitals_score  INTEGER,            -- 0-100
  vitals_band   TEXT,               -- HEALTHY | NEEDS_CARE | AT_RISK | CRITICAL
  spoofable     TEXT,               -- SPOOFABLE | PARTIAL | PROTECTED

  -- Which tool it came through, and where from. Not the IP: the promise that
  -- no history is built against an address stays true, and an address is the
  -- one field here that would make this personal data rather than a list of
  -- domains.
  source        TEXT    NOT NULL,   -- checkup | lookup | flatten | bimi
  country       TEXT
);

-- The working order: worst domains first, then most recently seen.
CREATE INDEX IF NOT EXISTS idx_checkups_score ON checkups (vitals_score ASC, last_seen DESC);
-- Deleting past the retention window, and "what came in today".
CREATE INDEX IF NOT EXISTS idx_checkups_seen  ON checkups (last_seen DESC);
-- The highest-intent slice: a domain anybody can send as, checked by somebody
-- who now knows it.
CREATE INDEX IF NOT EXISTS idx_checkups_spoof ON checkups (spoofable, last_seen DESC);
