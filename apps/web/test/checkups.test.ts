import { describe, expect, it, vi } from 'vitest';
import {
  normalizeCheckup,
  normalizeScore,
  recordCheckup,
  writeCheckup,
  writeFinalScore,
} from '../src/lib/checkups';

/**
 * The one table a checkup writes to.
 *
 * Two properties matter more than the SQL. Nothing a person will read should
 * ever contain junk, and nothing here may ever break a diagnosis: somebody is
 * waiting on the other end of that request and a busy table is our problem,
 * not theirs.
 */

/** A D1 stand-in that records what it was asked to do. */
function fakeDb(onRun: () => void = () => {}, changes = 1) {
  const calls: { sql: string; args: unknown[] }[] = [];
  const db = {
    prepare(sql: string) {
      return {
        bind(...args: unknown[]) {
          return {
            run: async () => {
              calls.push({ sql, args });
              onRun();
              // `meta.changes` is how D1 reports whether an UPDATE matched,
              // which is the whole answer for a write that must never insert.
              return { success: true, meta: { changes } };
            },
          };
        },
      };
    },
  };
  return { db: db as unknown as D1Database, calls };
}

describe('what gets written down', () => {
  it('stores the domain, the verdict and where it came from', async () => {
    const { db, calls } = fakeDb();
    const written = await writeCheckup(db, {
      domain: 'Example.COM',
      source: 'checkup',
      vitalsScore: 42,
      vitalsBand: 'AT_RISK',
      spoofable: 'SPOOFABLE',
      country: 'GB',
    });

    expect(written).toBe(true);
    expect(calls[0]?.args).toEqual(['example.com', 'checkup', 42, 'AT_RISK', 'SPOOFABLE', 'GB']);
  });

  it('counts a repeat check rather than adding a second row', async () => {
    // The question this table answers is "which domains are struggling", which
    // is a list of domains. A popular domain checked forty times is one
    // prospect, not forty.
    const { db, calls } = fakeDb();
    await writeCheckup(db, { domain: 'example.com', source: 'checkup' });

    expect(calls[0]?.sql).toMatch(/ON CONFLICT\(domain\) DO UPDATE/);
    expect(calls[0]?.sql).toMatch(/checks\s*=\s*checks \+ 1/);
  });

  it('does not let a Lab tool erase a score the checkup found', async () => {
    // A single-record tool has no total to give. Writing its null over a real
    // result would empty the column that makes the list worth working.
    const { db, calls } = fakeDb();
    await writeCheckup(db, { domain: 'example.com', source: 'lookup' });

    expect(calls[0]?.sql).toMatch(/vitals_score = COALESCE\(excluded\.vitals_score/);
    expect(calls[0]?.args[2]).toBeNull();
  });

  it('records nothing that identifies a person', async () => {
    // The privacy page promises this in as many words. The column list is the
    // enforcement: there is nowhere to put an address even by accident.
    const { db, calls } = fakeDb();
    await writeCheckup(db, { domain: 'example.com', source: 'checkup', country: 'IN' });

    const sql = calls[0]?.sql ?? '';
    for (const forbidden of ['ip', 'address', 'user_agent', 'referrer', 'session', 'email']) {
      expect(sql.toLowerCase()).not.toContain(forbidden);
    }
  });
});

describe('what does not get written down', () => {
  it.each([
    ['empty', ''],
    ['no dot', 'localhost'],
    ['whitespace only', '   '],
    ['longer than a domain can be', `${'a'.repeat(250)}.com`],
  ])('refuses %s', (_label, domain) => {
    expect(normalizeCheckup({ domain, source: 'checkup' })).toBeNull();
  });

  it('refuses a source that is not one of the tools', () => {
    expect(
      normalizeCheckup({ domain: 'example.com', source: 'sneaky' as never }),
    ).toBeNull();
  });

  it('drops a score that could not have come from the scorer', () => {
    const row = normalizeCheckup({ domain: 'example.com', source: 'checkup', vitalsScore: 900 });
    expect(row?.vitalsScore).toBeNull();
  });

  it('strips the trailing dot off a fully qualified name', () => {
    // `example.com.` and `example.com` are the same domain, and two rows for
    // one prospect is exactly what the primary key is there to prevent.
    expect(normalizeCheckup({ domain: 'Example.com.', source: 'checkup' })?.domain).toBe(
      'example.com',
    );
  });
});

describe('a checkup never fails because of this', () => {
  it('swallows a database that throws', async () => {
    const { db } = fakeDb(() => {
      throw new Error('D1_ERROR: database is locked');
    });

    await expect(writeCheckup(db, { domain: 'example.com', source: 'checkup' })).resolves.toBe(
      false,
    );
  });

  it('does nothing at all when there is no binding', async () => {
    // The stub for `cloudflare:workers` has no bindings, which is the case a
    // misconfigured deploy would hit.
    await expect(recordCheckup({ domain: 'example.com', source: 'checkup' })).resolves.toBe(false);
  });

  it('deletes past the retention window rather than keeping an archive', async () => {
    const { db, calls } = fakeDb();
    const { prune, RETENTION_DAYS } = await import('../src/lib/checkups');

    vi.setSystemTime(new Date('2026-06-01T00:00:00Z'));
    await prune(db);

    expect(RETENTION_DAYS).toBe(90);
    expect(calls[0]?.sql).toMatch(/DELETE FROM checkups WHERE last_seen < \?/);
    expect(calls[0]?.args[0]).toBe('2026-03-03T00:00:00Z');
    vi.useRealTimers();
  });
});

/**
 * The score correction, which is the one value here that arrives from a page
 * rather than from an engine.
 *
 * A checkup is three requests: `/api/check` writes the row, then the DKIM probe
 * and the full chain walk land in the browser, and both can only add findings.
 * So the score the endpoint records is never worse than the truth, and the
 * table was holding domains at 85 and HEALTHY under a page reading 78 and NEEDS
 * CARE. The browser reports the finished number back, and everything
 * below is what keeps that narrow.
 */
describe('correcting a score to the one that was shown', () => {
  const good = {
    domain: 'example.com',
    vitalsScore: 78,
    vitalsBand: 'NEEDS_CARE',
    spoofable: 'PROTECTED',
  };

  it('updates the row and marks the score as the one the visitor read', async () => {
    const { db, calls } = fakeDb();
    await expect(writeFinalScore(db, good)).resolves.toBe(true);

    expect(calls[0]?.sql).toMatch(/score_complete\s*=\s*1/);
    expect(calls[0]?.args).toEqual([78, 'NEEDS_CARE', 'PROTECTED', 'example.com']);
  });

  it('updates and never inserts', async () => {
    // The trust model in one assertion. The number comes over the wire, so it
    // may only ever correct a row a checkup on this Worker already created.
    const { db, calls } = fakeDb();
    await writeFinalScore(db, good);

    expect(calls[0]?.sql).toMatch(/^UPDATE checkups/);
    expect(calls[0]?.sql).not.toMatch(/INSERT/i);
  });

  it('does not count a second visit', async () => {
    // One checkup is one visit, however many times its score is refined.
    const { db, calls } = fakeDb();
    await writeFinalScore(db, good);

    expect(calls[0]?.sql).not.toMatch(/checks/);
  });

  it('reports a miss rather than inventing a row', async () => {
    // A checkup served from the response cache never wrote a row. Nothing to
    // correct is not an error.
    const { db } = fakeDb(() => {}, 0);
    await expect(writeFinalScore(db, good)).resolves.toBe(false);
  });

  it('swallows a database that throws', async () => {
    const { db } = fakeDb(() => {
      throw new Error('D1_ERROR: database is locked');
    });
    await expect(writeFinalScore(db, good)).resolves.toBe(false);
  });
});

describe('what a page is not allowed to put in the table', () => {
  const good = {
    domain: 'example.com',
    vitalsScore: 78,
    vitalsBand: 'NEEDS_CARE',
    spoofable: 'PROTECTED',
  };

  it.each([
    ['a score above the scale', { vitalsScore: 900 }],
    ['a negative score', { vitalsScore: -1 }],
    ['a score that is not a number', { vitalsScore: Number.NaN }],
    ['a band nobody defines', { vitalsBand: 'EXCELLENT' }],
    ['an empty band', { vitalsBand: '' }],
    ['a verdict nobody defines', { spoofable: 'FINE' }],
    ['a domain with no dot', { domain: 'localhost' }],
    ['a domain longer than a domain can be', { domain: `${'a'.repeat(250)}.com` }],
  ])('refuses %s', (_label, override) => {
    expect(normalizeScore({ ...good, ...override })).toBeNull();
  });

  it('accepts every band and verdict the scorer can produce', () => {
    // If the scorer gains a band, this fails rather than the column silently
    // dropping the rows that carry it.
    for (const vitalsBand of ['HEALTHY', 'NEEDS_CARE', 'AT_RISK', 'CRITICAL']) {
      for (const spoofable of ['PROTECTED', 'PARTIAL', 'SPOOFABLE']) {
        expect(normalizeScore({ ...good, vitalsBand, spoofable })).not.toBeNull();
      }
    }
  });

  it('normalises the domain the same way the insert does', () => {
    // Otherwise the UPDATE misses the row the INSERT created.
    expect(normalizeScore({ ...good, domain: 'Example.com.' })?.domain).toBe('example.com');
  });
});

describe('a fresh checkup unsettles the score it overwrites', () => {
  it('clears the flag when a new checkup writes its provisional number', async () => {
    // The row was settled by somebody else's result screen. A new checkup
    // overwrites the score with one that has no DKIM in it, so the flag has to
    // go with it or the table claims a provisional number is final.
    const { db, calls } = fakeDb();
    await writeCheckup(db, { domain: 'example.com', source: 'checkup', vitalsScore: 85 });

    expect(calls[0]?.sql).toMatch(/score_complete = CASE/);
    expect(calls[0]?.sql).toMatch(/WHEN excluded\.vitals_score IS NULL THEN checkups\.score_complete/);
  });
});
