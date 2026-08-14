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
           country      = COALESCE(excluded.country,      checkups.country)`,
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
