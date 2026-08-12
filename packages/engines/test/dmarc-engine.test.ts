import { describe, expect, it } from 'vitest';
import { DohResolver } from '@maildoc/resolver';
import { createMockDoh, type MockDohOptions, type MockZone } from '@maildoc/resolver/testing';
import { analyzeDmarc, stepUp, type DmarcEngineOptions } from '../src/index.js';

interface RunOptions extends DmarcEngineOptions {
  domain?: string;
  mock?: MockDohOptions;
  budget?: number;
  maxQueries?: number;
}

async function run(zone: MockZone, options: RunOptions = {}) {
  const { domain = 'example.com', mock: mockOptions, budget, maxQueries, ...engineOptions } = options;
  const mock = createMockDoh(zone, mockOptions);
  const resolver = new DohResolver({
    fetchImpl: mock.fetch,
    timeoutMs: 20,
    ...(budget === undefined ? {} : { budget }),
  });
  const analysis = await analyzeDmarc(domain, resolver, {
    verifyApex: false,
    ...(maxQueries === undefined ? {} : { maxQueries }),
    ...engineOptions,
  });
  return { analysis, codes: analysis.conditions.map((c) => c.code), mock, resolver };
}

const zoneWith = (record: string, name = '_dmarc.example.com'): MockZone => ({
  'example.com': { A: ['203.0.113.10'] },
  [name]: { TXT: [record] },
});

describe('DMARC — tree walk (RFC 9989 §4.10)', () => {
  it('strips the leftmost label while under eight labels', () => {
    expect(stepUp('mail.corp.example.com')).toBe('corp.example.com');
    expect(stepUp('example.com')).toBe('com');
    expect(stepUp('com')).toBeNull();
  });

  it('collapses to seven labels when there are eight or more', () => {
    // The spec's shortcut: a domain with tens of labels must not cost tens of
    // queries.
    const deep = 'a.b.c.d.e.f.g.h.i.j.example.com';
    expect(deep.split('.')).toHaveLength(12);
    expect(stepUp(deep)).toBe('f.g.h.i.j.example.com');
    expect(stepUp(deep)?.split('.')).toHaveLength(7);
  });

  it('finds the record at the author domain and applies p', async () => {
    const { analysis, codes } = await run(zoneWith('v=DMARC1; p=reject; rua=mailto:d@example.com'));

    expect(analysis.found).toBe(true);
    expect(analysis.discovery.source).toBe('author');
    expect(analysis.discovery.queries).toBe(1);
    expect(analysis.appliedPolicy).toBe('reject');
    expect(codes).toEqual([]);
  });

  it('walks up to a parent and applies sp, not p', async () => {
    // This is the distinction other checkers get wrong: a subdomain inheriting
    // a parent record is governed by sp.
    const { analysis, codes } = await run(
      {
        'mail.example.com': { A: ['203.0.113.10'] },
        '_dmarc.example.com': {
          TXT: ['v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com'],
        },
      },
      { domain: 'mail.example.com' },
    );

    expect(analysis.discovery.source).toBe('parent');
    expect(analysis.discovery.foundAt).toBe('example.com');
    expect(analysis.policy).toBe('reject');
    expect(analysis.appliedPolicy).toBe('none');
    expect(codes).toContain('DMARC_POLICY_INHERITED');
    expect(codes).toContain('DMARC_P_NONE');
  });

  it('never exceeds eight queries, however deep the domain is', async () => {
    // The collapse shortcut is what makes this true: a 13-label domain costs
    // the same eight queries as any other, which is exactly why the spec has
    // it. The walk therefore completes normally rather than being capped.
    const deep = 'a.b.c.d.e.f.g.h.i.j.k.example.com';
    const { analysis, codes } = await run({ [deep]: { A: ['203.0.113.10'] } }, { domain: deep });

    expect(deep.split('.')).toHaveLength(13);
    expect(analysis.discovery.queries).toBeLessThanOrEqual(8);
    expect(analysis.discovery.capped).toBe(false);
    expect(codes).toContain('DMARC_RECORD_MISSING');
  });

  it('reports a capped walk when the query budget is squeezed', async () => {
    // The orchestrator can hand DMARC a smaller slice when other records have
    // eaten the subrequest budget. Then we must say discovery was incomplete,
    // not that the domain has no policy.
    const { analysis, codes } = await run(
      {
        'deep.sub.example.com': { A: ['203.0.113.10'] },
        '_dmarc.example.com': { TXT: ['v=DMARC1; p=reject; rua=mailto:d@example.com'] },
      },
      { domain: 'deep.sub.example.com', maxQueries: 2 },
    );

    expect(analysis.discovery.capped).toBe(true);
    expect(codes).toContain('DMARC_TREE_WALK_CAPPED');
    expect(codes).not.toContain('DMARC_RECORD_MISSING');
  });

  it('reports a missing record when the walk completes without one', async () => {
    const { analysis, codes } = await run({ 'example.com': { A: ['203.0.113.10'] } });
    expect(codes).toEqual(['DMARC_RECORD_MISSING']);
    expect(analysis.found).toBe(false);
    expect(analysis.effectivePolicy).toBe('none');
  });

  it('discards multiple records at one name, as receivers do', async () => {
    const { analysis, codes } = await run({
      'example.com': { A: ['203.0.113.10'] },
      '_dmarc.example.com': {
        TXT: ['v=DMARC1; p=reject; rua=mailto:a@example.com', 'v=DMARC1; p=none'],
      },
    });

    expect(codes).toContain('DMARC_MULTIPLE_RECORDS');
    expect(analysis.conditions[0]?.severity).toBe('CRITICAL');
  });
});

describe('DMARC — policy', () => {
  it('treats a record with no p as p=none rather than broken', async () => {
    // RFC 9989 §4.8 — the record is valid; it simply protects nothing.
    const { analysis, codes } = await run(zoneWith('v=DMARC1; rua=mailto:d@example.com'));

    expect(codes).toContain('DMARC_P_MISSING');
    expect(codes).not.toContain('DMARC_UNPARSEABLE');
    expect(analysis.policy).toBe('none');
    expect(analysis.ignored).toBe(false);
    expect(analysis.conditions.find((c) => c.code === 'DMARC_P_MISSING')?.severity).toBe('HIGH');
  });

  it('flags an invalid policy value', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=block; rua=mailto:d@example.com'));
    expect(codes).toContain('DMARC_P_INVALID');
  });

  it('calls p=none monitoring only', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=none; rua=mailto:d@example.com'));
    expect(codes).toEqual(['DMARC_P_NONE']);
  });

  it('calls p=quarantine one step short', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=quarantine; rua=mailto:d@example.com'));
    expect(codes).toEqual(['DMARC_P_QUARANTINE']);
  });

  it('says nothing about a clean p=reject', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=reject; rua=mailto:d@example.com'));
    expect(codes).toEqual([]);
  });

  it('flags a weaker subdomain policy', async () => {
    const { analysis, codes } = await run(
      zoneWith('v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com'),
    );
    expect(codes).toContain('DMARC_WEAKER_SP');
    expect(analysis.subdomainPolicy).toBe('none');
    expect(analysis.conditions.find((c) => c.code === 'DMARC_WEAKER_SP')?.why).toContain(
      'invoices.example.com',
    );
  });

  it('flags a weaker non-existent-subdomain policy', async () => {
    const { codes } = await run(
      zoneWith('v=DMARC1; p=reject; sp=reject; np=none; rua=mailto:d@example.com'),
    );
    expect(codes).toContain('DMARC_WEAKER_NP');
  });
});

describe('DMARC — test mode', () => {
  it('reports that t=y silently disables enforcement', async () => {
    const { analysis, codes } = await run(
      zoneWith('v=DMARC1; p=reject; t=y; rua=mailto:d@example.com'),
    );

    expect(codes).toContain('DMARC_STALE_TEST_MODE');
    expect(analysis.appliedPolicy).toBe('reject');
    // What receivers actually do is what matters for spoofability.
    expect(analysis.effectivePolicy).toBe('none');
    expect(analysis.conditions[0]?.severity).toBe('CRITICAL');
  });

  it('leaves t=y alone when the policy is already none', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=none; t=y; rua=mailto:d@example.com'));
    expect(codes).not.toContain('DMARC_STALE_TEST_MODE');
  });

  it('flags an invalid t value', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=reject; t=maybe; rua=mailto:d@example.com'));
    expect(codes).toContain('DMARC_T_INVALID');
  });
});

describe('DMARC — syntax', () => {
  it('reports a wrong version tag as fatal', async () => {
    const { analysis, codes } = await run(zoneWith('v=DMARC2; p=reject; rua=mailto:d@example.com'));
    expect(codes).toContain('DMARC_V_CASE_INVALID');
    expect(analysis.ignored).toBe(true);
    expect(analysis.effectivePolicy).toBe('none');
  });

  it('reports a misplaced version tag as fatal', async () => {
    const { analysis, codes } = await run(zoneWith('p=reject; v=DMARC1; rua=mailto:d@example.com'));
    expect(codes).toContain('DMARC_V_OUT_OF_ORDER');
    expect(analysis.ignored).toBe(true);
  });

  it('flags duplicate tags', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=none; p=reject; rua=mailto:d@example.com'));
    expect(codes).toContain('DMARC_DUPLICATE_TAG');
  });

  it('flags a segment that is not tag=value', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=reject; rua mailto:d@example.com'));
    expect(codes).toContain('DMARC_SYNTAX_DELIMITER');
  });

  it('ignores unknown tags, as the RFC requires', async () => {
    const { codes } = await run(
      zoneWith('v=DMARC1; p=reject; rua=mailto:d@example.com; futuretag=1'),
    );
    expect(codes).toEqual([]);
  });

  it('accepts whitespace around tags, which the ABNF allows', async () => {
    const { codes } = await run(zoneWith('v=DMARC1;  p = reject ; rua = mailto:d@example.com'));
    expect(codes).toEqual([]);
  });

  it('reports a record that only carries a version', async () => {
    const { codes } = await run(zoneWith('v=DMARC1'));
    expect(codes).toContain('DMARC_EMPTY_RECORD');
  });

  it('flags retired tags', async () => {
    const { codes } = await run(
      zoneWith('v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com'),
    );
    expect(codes).toContain('DMARC_OBSOLETE_TAGS');
  });
});

describe('DMARC — alignment and psd', () => {
  it('notes strict alignment as an advisory', async () => {
    const { analysis, codes } = await run(
      zoneWith('v=DMARC1; p=reject; adkim=s; aspf=s; rua=mailto:d@example.com'),
    );
    expect(codes).toContain('DMARC_ADKIM_STRICT_ADV');
    expect(codes).toContain('DMARC_ASPF_STRICT_ADV');
    expect(analysis.alignment).toEqual({ dkim: 's', spf: 's' });
    expect(analysis.status).toBe('HEALTHY');
  });

  it('accepts psd=u, which the current spec added', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=reject; psd=u; rua=mailto:d@example.com'));
    expect(codes).toEqual([]);
  });

  it('flags psd=y on an ordinary domain', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=reject; psd=y; rua=mailto:d@example.com'));
    expect(codes).toContain('DMARC_ORG_DOMAIN_IS_PSD');
  });

  it('flags an invalid psd value', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=reject; psd=maybe; rua=mailto:d@example.com'));
    expect(codes).toContain('DMARC_PSD_INVALID');
  });
});

describe('DMARC — reporting', () => {
  it('flags a missing rua', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=none'));
    expect(codes).toContain('DMARC_RUA_MISSING');
  });

  it('calls out enforcement with no visibility', async () => {
    const { analysis, codes } = await run(zoneWith('v=DMARC1; p=reject'));
    expect(codes).toContain('DMARC_BLIND_REJECT');
    expect(analysis.conditions.find((c) => c.code === 'DMARC_BLIND_REJECT')?.severity).toBe(
      'CRITICAL',
    );
  });

  it('does not call it blind when test mode means nothing is enforced', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=reject; t=y'));
    expect(codes).not.toContain('DMARC_BLIND_REJECT');
  });

  it('flags a destination with no mailto:', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=reject; rua=dmarc@example.com'));
    expect(codes).toContain('DMARC_RUA_NO_MAILTO');
  });

  it('flags space-separated destinations', async () => {
    const { codes } = await run(
      zoneWith('v=DMARC1; p=reject; rua=mailto:a@example.com mailto:b@example.com'),
    );
    expect(codes).toContain('DMARC_RUA_BAD_DELIMITER');
  });

  it('accepts a valid size modifier', async () => {
    const { codes } = await run(zoneWith('v=DMARC1; p=reject; rua=mailto:d@example.com!10m'));
    expect(codes).toEqual([]);
  });

  it('flags an invalid fo value', async () => {
    const { codes } = await run(
      zoneWith('v=DMARC1; p=reject; fo=9; rua=mailto:d@example.com'),
    );
    expect(codes).toContain('DMARC_FO_INVALID');
  });

  it('accepts a colon-separated fo list', async () => {
    const { codes } = await run(
      zoneWith('v=DMARC1; p=reject; fo=d:s; rua=mailto:d@example.com'),
    );
    expect(codes).toEqual([]);
  });
});

describe('DMARC — external destination verification', () => {
  const external = 'v=DMARC1; p=reject; rua=mailto:reports@agency.example.net';

  it('passes when the destination has authorised the domain', async () => {
    const { analysis, codes } = await run({
      'example.com': { A: ['203.0.113.10'] },
      '_dmarc.example.com': { TXT: [external] },
      'example.com._report._dmarc.agency.example.net': { TXT: ['v=DMARC1'] },
    });

    expect(codes).toEqual([]);
    expect(analysis.edv).toEqual([{ destination: 'agency.example.net', status: 'AUTHORIZED' }]);
  });

  it('reports a destination that never authorised the domain', async () => {
    const { analysis, codes } = await run({
      'example.com': { A: ['203.0.113.10'] },
      '_dmarc.example.com': { TXT: [external] },
    });

    expect(codes).toContain('DMARC_EDV_MISSING');
    expect(analysis.edv[0]?.status).toBe('MISSING');
    expect(analysis.conditions.find((c) => c.code === 'DMARC_EDV_MISSING')?.fix).toContain(
      'example.com._report._dmarc.agency.example.net',
    );
  });

  it('reports a malformed authorisation record', async () => {
    const { codes } = await run({
      'example.com': { A: ['203.0.113.10'] },
      '_dmarc.example.com': { TXT: [external] },
      'example.com._report._dmarc.agency.example.net': { TXT: ['hello'] },
    });
    expect(codes).toContain('DMARC_EDV_MALFORMED');
  });

  it('never blames the domain when the lookup itself failed', async () => {
    // A slow nameserver at the destination is not a misconfiguration here.
    const { analysis, codes } = await run(
      {
        'example.com': { A: ['203.0.113.10'] },
        '_dmarc.example.com': { TXT: [external] },
      },
      {
        mock: {
          fail: (call) => (call.name.includes('_report._dmarc') ? 'TIMEOUT' : undefined),
        },
      },
    );

    expect(codes).toContain('DMARC_EDV_UNVERIFIED');
    expect(codes).not.toContain('DMARC_EDV_MISSING');
    expect(analysis.edv[0]?.status).toBe('UNVERIFIED');
    expect(analysis.conditions.find((c) => c.code === 'DMARC_EDV_UNVERIFIED')?.severity).toBe(
      'LOW',
    );
  });

  it('does not verify destinations inside the domain itself', async () => {
    const { analysis, mock } = await run(
      zoneWith('v=DMARC1; p=reject; rua=mailto:dmarc@example.com,mailto:d@mail.example.com'),
    );
    expect(analysis.edv).toEqual([]);
    expect(mock.calls.some((call) => call.name.includes('_report'))).toBe(false);
  });
});

describe('DMARC — never a wrong answer', () => {
  it('reports a resolver timeout instead of a missing record', async () => {
    const { analysis, codes } = await run(zoneWith('v=DMARC1; p=reject'), {
      mock: { fail: () => 'TIMEOUT' },
    });

    expect(codes).toEqual(['RESOLVER_TIMEOUT']);
    expect(codes).not.toContain('DMARC_RECORD_MISSING');
    expect(analysis.found).toBe(false);
  });

  it('produces fully interpolated conditions', async () => {
    const { analysis } = await run(
      zoneWith('v=DMARC1; p=quarantine; sp=none; psd=y; pct=50; fo=9; rua=bad'),
    );
    expect(analysis.conditions.length).toBeGreaterThan(3);
    for (const condition of analysis.conditions) {
      expect(`${condition.title} ${condition.why} ${condition.fix}`).not.toMatch(/\{[a-z_]+\}/);
    }
  });
});

describe('external destination severity', () => {
  const unauthorised: MockZone = {
    'example.com': { TXT: ['v=spf1 -all'] },
    '_dmarc.example.com': {
      TXT: ['v=DMARC1; p=reject; rua=mailto:d@example.com,mailto:d@vendor.example'],
    },
    // vendor.example publishes no authorisation record.
  };

  it('is not critical while reports still reach an address on the domain', async () => {
    const { codes } = await run(unauthorised);

    expect(codes).toContain('DMARC_EDV_MISSING_PARTIAL');
    expect(codes).not.toContain('DMARC_EDV_MISSING');
  });

  it('is critical when every destination is external and unauthorised', async () => {
    const { codes } = await run({
      ...unauthorised,
      '_dmarc.example.com': { TXT: ['v=DMARC1; p=reject; rua=mailto:d@vendor.example'] },
    });

    // Nothing arrives anywhere: the owner is blind to their own mail.
    expect(codes).toContain('DMARC_EDV_MISSING');
    expect(codes).not.toContain('DMARC_EDV_MISSING_PARTIAL');
  });

  it('says nothing when the destination authorises properly', async () => {
    const { codes } = await run({
      ...unauthorised,
      'example.com._report._dmarc.vendor.example': { TXT: ['v=DMARC1'] },
    });

    expect(codes).not.toContain('DMARC_EDV_MISSING');
    expect(codes).not.toContain('DMARC_EDV_MISSING_PARTIAL');
  });
});
