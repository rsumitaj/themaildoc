import { env } from 'cloudflare:workers';

/**
 * The record of which domains have been examined.
 *
 * Everything else in the product reads public DNS and forgets. This is the one
 * place a checkup leaves anything behind, it is stated on `/privacy` in the
 * same words as here, and it holds a domain and a score. It does not hold an
 * address, a session or anything that says who ran the check, because a domain
 * on its own is a thing on the internet and a domain tied to a person is not.
 *
 * A write here can never affect a checkup. Every function below swallows its
 * own failures: a diagnosis that a stranger is waiting for does not fail
 * because a table was busy.
 */

/** Which tool the domain came through. Also the column's allowed values. */
export type CheckupSource = 'checkup' | 'lookup' | 'flatten' | 'bimi';

export interface CheckupRecord {
  domain: string;
  source: CheckupSource;
  /** Present only for a full checkup. A single-record tool has no total. */
  vitalsScore?: number | null;
  vitalsBand?: string | null;
  spoofable?: string | null;
  country?: string | null;
}

/** The bands a Vitals score can fall in. Also the column's allowed values. */
const BANDS = new Set(['HEALTHY', 'NEEDS_CARE', 'AT_RISK', 'CRITICAL']);

/** The spoofability verdicts. Also the column's allowed values. */
const VERDICTS = new Set(['PROTECTED', 'PARTIAL', 'SPOOFABLE']);

/**
 * The finished score for a domain already in the table.
 *
 * A checkup is three requests. `/api/check` can write a row the moment it has
 * an answer, and the answer it has is missing DKIM and the full include chain,
 * both of which can only add findings — so the score it writes overstates the
 * domain's health every time either of them finds something. The number the
 * visitor actually reads is assembled in their browser, and this is how it gets
 * back.
 *
 * It updates and never inserts. That is the whole trust model: the score
 * arrives from a page rather than from a resolver, so it is only ever allowed
 * to correct a row that a checkup on this Worker already created, for a domain
 * this Worker already looked up. A caller who invents a domain gets nothing,
 * and a caller who invents a score for a real one moves a number in a
 * prospecting list — which is the reason the values are range-checked here and
 * the reason `checks` is deliberately not touched: one visit is one visit,
 * however many times its score is refined.
 */
export interface CheckupScore {
  domain: string;
  vitalsScore: number;
  vitalsBand: string;
  spoofable: string;
}

/** Rows are deleted this long after the last time the domain was checked. */
export const RETENTION_DAYS = 90;

/**
 * Prune every hundredth write.
 *
 * A `DELETE` on each insert would double the write cost to remove nothing
 * almost every time. A cron trigger would be tidier and needs a scheduled
 * handler the static adapter does not give us. Once in a hundred is often
 * enough that the window is honoured within an hour of normal traffic, and
 * cheap enough to be invisible.
 */
const PRUNE_EVERY = 100;
let writes = 0;

interface Env {
  LEADS?: D1Database;
}

/**
 * Record that a domain was examined. Never throws, never blocks a result.
 *
 * Returns whether a row was written, which is what the tests assert on. The
 * endpoints ignore it.
 */
export async function recordCheckup(entry: CheckupRecord): Promise<boolean> {
  const database = (env as Env).LEADS;
  if (!database) return false;
  return writeCheckup(database, entry);
}

/**
 * The row, as it will be stored, or null if it has no business being stored.
 *
 * Separated from the write so it can be tested without a database: what ends
 * up in a table a person reads is worth asserting.
 */
export function normalizeCheckup(entry: CheckupRecord): CheckupRecord | null {
  const domain = entry.domain.trim().toLowerCase().replace(/\.$/, '');

  // The endpoints normalise before they get here, so anything failing this is
  // a bug rather than a user. Storing it anyway would put junk in the list.
  if (!domain || domain.length > 253 || !domain.includes('.')) return null;
  if (!SOURCES.has(entry.source)) return null;

  return {
    domain,
    source: entry.source,
    vitalsScore: score(entry.vitalsScore),
    vitalsBand: text(entry.vitalsBand),
    spoofable: text(entry.spoofable),
    country: text(entry.country),
  };
}

const SOURCES = new Set<CheckupSource>(['checkup', 'lookup', 'flatten', 'bimi']);

/** Takes the database rather than reading it, so a test can pass a fake one. */
export async function writeCheckup(
  database: D1Database,
  entry: CheckupRecord,
): Promise<boolean> {
  const row = normalizeCheckup(entry);
  if (row === null) return false;

  try {
    /**
     * One row per domain. A repeat check moves `last_seen`, counts the visit
     * and overwrites the verdict, because the current state of the domain is
     * what makes it worth contacting, not the state it was in in June.
     *
     * `COALESCE` on the score keeps a real result from being erased by a later
     * single-record Lab check, which has no score to offer.
     *
     * `score_complete` is reset by a new checkup and only by a new checkup. The
     * score arriving here is the provisional one — nine records, no DKIM, a
     * bounded chain walk — so a row that was settled by a previous visitor's
     * result screen is unsettled again the moment a fresh checkup overwrites
     * its number, and stays that way until this visitor's screen reports back.
     * A Lab tool passes no score, so it must not clear the flag on one.
     */
    await database
      .prepare(
        `INSERT INTO checkups (domain, source, vitals_score, vitals_band, spoofable, country)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT(domain) DO UPDATE SET
           last_seen    = strftime('%Y-%m-%dT%H:%M:%SZ', 'now'),
           checks       = checks + 1,
           source       = excluded.source,
           vitals_score = COALESCE(excluded.vitals_score, checkups.vitals_score),
           vitals_band  = COALESCE(excluded.vitals_band,  checkups.vitals_band),
           spoofable    = COALESCE(excluded.spoofable,    checkups.spoofable),
           country      = COALESCE(excluded.country,      checkups.country),
           score_complete = CASE
             WHEN excluded.vitals_score IS NULL THEN checkups.score_complete
             ELSE 0
           END`,
      )
      .bind(row.domain, row.source, row.vitalsScore, row.vitalsBand, row.spoofable, row.country)
      .run();

    writes += 1;
    if (writes % PRUNE_EVERY === 0) await prune(database);
    return true;
  } catch {
    // A table that is busy, missing or migrating is not a reason to fail
    // somebody's checkup.
    return false;
  }
}

/**
 * Correct a row's score to the one the visitor was shown. Never throws.
 *
 * Returns whether a row was updated, which is what the tests assert on. A
 * `false` here is not an error: a domain whose checkup was served from cache
 * never wrote a row, so there is nothing to correct.
 */
export async function recordFinalScore(entry: CheckupScore): Promise<boolean> {
  const database = (env as Env).LEADS;
  if (!database) return false;
  return writeFinalScore(database, entry);
}

/** Takes the database rather than reading it, so a test can pass a fake one. */
export async function writeFinalScore(
  database: D1Database,
  entry: CheckupScore,
): Promise<boolean> {
  const row = normalizeScore(entry);
  if (row === null) return false;

  try {
    const result = await database
      .prepare(
        `UPDATE checkups
            SET vitals_score   = ?,
                vitals_band    = ?,
                spoofable      = ?,
                score_complete = 1
          WHERE domain = ?`,
      )
      .bind(row.vitalsScore, row.vitalsBand, row.spoofable, row.domain)
      .run();

    return (result.meta?.changes ?? 0) > 0;
  } catch {
    // Same rule as every other write here: a table that is busy or missing is
    // not a reason to fail anything a person is waiting for.
    return false;
  }
}

/**
 * The correction as it will be stored, or null if it has no business being
 * stored.
 *
 * Stricter than `normalizeCheckup` on purpose. Those values come from our own
 * engines; these come over the wire from a page, so a band or a verdict outside
 * the set the column is documented to hold is rejected outright rather than
 * truncated to forty characters and written.
 */
export function normalizeScore(entry: CheckupScore): CheckupScore | null {
  const domain = entry.domain.trim().toLowerCase().replace(/\.$/, '');
  if (!domain || domain.length > 253 || !domain.includes('.')) return null;

  const vitalsScore = score(entry.vitalsScore);
  if (vitalsScore === null) return null;

  const vitalsBand = text(entry.vitalsBand);
  if (vitalsBand === null || !BANDS.has(vitalsBand)) return null;

  const spoofable = text(entry.spoofable);
  if (spoofable === null || !VERDICTS.has(spoofable)) return null;

  return { domain, vitalsScore, vitalsBand, spoofable };
}

/** Delete everything past the retention window stated on `/privacy`. */
export async function prune(database: D1Database): Promise<void> {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 86_400_000)
    .toISOString()
    .slice(0, 19)
    .concat('Z');

  try {
    await database.prepare('DELETE FROM checkups WHERE last_seen < ?').bind(cutoff).run();
  } catch {
    /* the next write will try again */
  }
}

function text(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed === '' ? null : trimmed.slice(0, 40);
}

function score(value: number | null | undefined): number | null {
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  if (value < 0 || value > 100) return null;
  return Math.round(value);
}

/** The country Cloudflare attached to the request, if it attached one. */
export function countryOf(request: Request): string | null {
  const cf = (request as { cf?: { country?: string } }).cf;
  return typeof cf?.country === 'string' ? cf.country : null;
}
