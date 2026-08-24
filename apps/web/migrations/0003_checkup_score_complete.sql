-- Whether the score in a row is the score the visitor was shown.
--
-- A checkup arrives in three requests, because fifty subrequests is not enough
-- for one. `/api/check` reads nine records and can write a row immediately;
-- the DKIM probe and the deep SPF chain walk land afterwards, in the browser,
-- and both can only add findings. So the score `/api/check` knows is an
-- over-estimate of health by construction, and it was the one being stored: a
-- domain sat in this table at 85 and HEALTHY while the page that wrote the row
-- read 78 and NEEDS CARE.
--
-- The browser now reports the finished number back and this column records
-- which rows have had that happen. A row at 0 is provisional — the visitor
-- closed the tab, ran without JavaScript, or a leg failed — and its score
-- should be read as "no worse than this". A row at 1 is what the person saw.
--
-- Existing rows default to 0, which is the truth about them: every one was
-- written before this endpoint existed.
--
-- Apply with:
--   wrangler d1 execute maildoc-leads --remote --file=migrations/0003_checkup_score_complete.sql

ALTER TABLE checkups ADD COLUMN score_complete INTEGER NOT NULL DEFAULT 0;

-- The prospecting query is "worst first, and is that number trustworthy". Both
-- halves come off this index.
CREATE INDEX IF NOT EXISTS idx_checkups_final ON checkups (score_complete, vitals_score ASC);
