import { describe, expect, it, vi } from 'vitest';
import { normalizeCheckup, recordCheckup, writeCheckup } from '../src/lib/checkups';

/**
 * The one table a checkup writes to.
 *
 * Two properties matter more than the SQL. Nothing a person will read should
 * ever contain junk, and nothing here may ever break a diagnosis: somebody is
 * waiting on the other end of that request and a busy table is our problem,
 * not theirs.
 */

/** A D1 stand-in that records what it was asked to do. */
function fakeDb(onRun: () => void = () => {}) {
  const calls: { sql: string; args: unknown[] }[] = [];
  const db = {
    prepare(sql: string) {
      return {
        bind(...args: unknown[]) {
          return {
            run: async () => {
              calls.push({ sql, args });
              onRun();
              return { success: true };
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
