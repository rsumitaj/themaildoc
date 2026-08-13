import { describe, expect, it } from 'vitest';
import { createMockDoh, type MockZone } from '@maildoc/resolver/testing';
import { healthCheck } from '../src/index.js';

/**
 * The orchestrator is where the product either holds together or does not: one
 * shared subrequest budget, five engines, and a score a patient will act on.
 */

const MTA_STS_POLICY =
  'version: STSv1\nmode: enforce\nmx: mail1.example.com\nmx: mail2.example.com\nmax_age: 604800\n';

const healthy: MockZone = {
  'example.com': {
    TXT: ['v=spf1 include:_spf.example.com -all'],
    MX: ['10 mail1.example.com.', '20 mail2.example.com.'],
    A: ['203.0.113.10'],
    AAAA: ['2001:db8::1'],
    DNSKEY: { data: ['257 3 13 abc'], ad: true },
    CAA: ['0 issue "letsencrypt.org"'],
  },
  '_spf.example.com': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
  '_dmarc.example.com': { TXT: ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com'] },
  '_mta-sts.example.com': { TXT: ['v=STSv1; id=20260101000000'] },
  '_smtp._tls.example.com': { TXT: ['v=TLSRPTv1; rua=mailto:tls@example.com'] },
  'default._bimi.example.com': {
    TXT: ['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'],
  },
  'mail1.example.com': { A: ['203.0.113.1'] },
  'mail2.example.com': { A: ['203.0.113.2'] },
  '1.113.0.203.in-addr.arpa': { PTR: ['mail1.example.com.'] },
  '2.113.0.203.in-addr.arpa': { PTR: ['mail2.example.com.'] },
};

const naked: MockZone = {
  'example.com': { A: ['203.0.113.10'] },
};

/**
 * A domain locked out of the mail business entirely: nothing may send as it,
 * nothing may be delivered to it, and DMARC refuses anything that tries. This
 * is the real configuration on example.com, and it is what the guidance for
 * parked domains asks for.
 */
const parked: MockZone = {
  'example.com': {
    TXT: ['v=spf1 -all'],
    MX: ['0 .'],
    A: ['203.0.113.10'],
  },
  '_dmarc.example.com': { TXT: ['v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s'] },
};

/**
 * DNS comes from the mock zone; the MTA-STS policy file comes from a stand-in
 * web server, because that check is the one HTTPS fetch in the product.
 */
const run = (zone: MockZone, options: Parameters<typeof healthCheck>[1] = {}) => {
  const mock = createMockDoh(zone);
  const fetchImpl = (async (url: string, init?: RequestInit) => {
    if (url.includes('/.well-known/mta-sts.txt')) return new Response(MTA_STS_POLICY, { status: 200 });
    return mock.fetch(url, init);
  }) as typeof mock.fetch;

  return healthCheck('example.com', {
    fetchImpl,
    timeoutMs: 20,
    verify: false,
    ...options,
  }).then((result) => ({ result, mock }));
};

describe('healthCheck — a healthy domain', () => {
  it('gives a clean bill of health', async () => {
    const { result } = await run(healthy);

    expect(result.vitals.score).toBe(100);
    expect(result.vitals.band).toBe('HEALTHY');
    expect(result.conditions).toEqual([]);
    expect(result.spoofability.verdict).toBe('PROTECTED');
  });

  it('summarises every record for the status row', async () => {
    const { result } = await run(healthy);
    const records = Object.fromEntries(result.records.map((r) => [r.record, r]));

    expect(records['SPF']?.summary).toContain('1 of 10 lookups');
    expect(records['DMARC']?.summary).toContain('reject');
    expect(records['MX']?.summary).toContain('2 mail exchangers');
    expect(records['DNSSEC']?.summary).toBe('Signed and validating');
    expect(records['MTASTS']?.summary).toContain('enforce');
    expect(records['TLSRPT']?.summary).toContain('1 reporting destination');
    expect(records['CAA']?.summary).toContain('1 authorised issuer');
    expect(records['PTR']?.summary).toContain('2 of 2 confirmed');
    expect(result.records).toHaveLength(10);
    expect(result.records.every((r) => r.status === 'HEALTHY')).toBe(true);
  });
});

describe('healthCheck — a domain with nothing', () => {
  it('finds the critical conditions and scores accordingly', async () => {
    const { result } = await run(naked);
    const codes = result.conditions.map((c) => c.code);

    expect(codes).toContain('SPF_RECORD_MISSING');
    expect(codes).toContain('DMARC_RECORD_MISSING');
    expect(codes).toContain('MX_MISSING');
    // Anyone can send as this domain, so it is capped into the critical band
    // however tidy the rest of its DNS is.
    expect(result.spoofability.verdict).toBe('SPOOFABLE');
    expect(result.vitals.score).toBeLessThanOrEqual(39);
    expect(result.vitals.band).toBe('CRITICAL');
  });

  it('says plainly that the domain can be spoofed', async () => {
    const { result } = await run(naked);

    expect(result.spoofability.verdict).toBe('SPOOFABLE');
    expect(result.spoofability.headline).toContain('spoofed right now');
    expect(result.spoofability.reasons.join(' ')).toContain('no DMARC record');
  });

  it('triages the chart most severe first', async () => {
    const { result } = await run(naked);
    const severities = result.conditions.map((c) => c.severity);
    const rank = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 } as const;
    const ranks = severities.map((s) => rank[s]);
    expect(ranks).toEqual([...ranks].sort((a, b) => a - b));
  });
});

describe('healthCheck — a parked domain', () => {
  it('does not ask a domain that sends no mail for outbound protection', async () => {
    const { result } = await run(parked);
    const codes = result.conditions.map((condition) => condition.code);

    // Nothing may send as it, so there is no legitimate traffic to be blind to
    // and no logo to show beside mail it does not send.
    expect(codes).not.toContain('DMARC_BLIND_REJECT');
    expect(codes).not.toContain('DMARC_RUA_MISSING');
    expect(codes).not.toContain('BIMI_MISSING');
  });

  it('does not ask a domain that receives no mail to protect its servers', async () => {
    const { result } = await run(parked);
    const codes = result.conditions.map((condition) => condition.code);

    // Both protect mail in transit to your mail servers. There are none.
    expect(codes).not.toContain('MTASTS_MISSING');
    expect(codes).not.toContain('TLSRPT_MISSING');
  });

  it('scores it as the healthy configuration it is', async () => {
    // This is the regression that mattered: example.com, configured exactly
    // the way the guidance says to configure a domain nobody should send as,
    // was scored 4 out of 100 and called a critical condition.
    const { result } = await run(parked);

    expect(result.vitals.score).toBeGreaterThanOrEqual(85);
    expect(result.vitals.band).toBe('HEALTHY');
    expect(result.spoofability.verdict).toBe('PROTECTED');
  });

  it('agrees with itself: no card counts a finding the chart does not list', async () => {
    // The cards were built before the suppression was applied, so DMARC showed
    // a red dot reading "4 conditions" above a chart that listed none of them.
    const { result } = await run(parked);
    const charted = result.conditions.length;
    const counted = result.records.reduce((total, record) => total + record.conditionCount, 0);

    expect(counted).toBe(charted);
    expect(result.records.every((record) => record.status !== 'CRITICAL')).toBe(true);
  });

  it('names the all mechanism in full, not as a bare qualifier', async () => {
    const { result } = await run(parked);
    const spf = result.records.find((record) => record.record === 'SPF');

    expect(spf?.summary).toContain('-all');
  });

  it('still says out loud that the domain accepts no mail, at no cost', async () => {
    const { result } = await run(parked);
    const nullMx = result.conditions.find((condition) => condition.code === 'MX_NULL');

    expect(nullMx).toBeDefined();
    expect(nullMx?.deduction).toBe(0);
  });

  it('keeps asking a normal domain for all of it', async () => {
    // The suppression must key off the domain's own statements rather than
    // firing for everybody. A domain with real mail exchangers and real
    // senders still owes MTA-STS, TLS-RPT and a reporting address.
    const { result } = await run({
      'example.com': {
        TXT: ['v=spf1 ip4:198.51.100.0/24 -all'],
        MX: ['10 mail1.example.com.'],
      },
      '_dmarc.example.com': { TXT: ['v=DMARC1; p=reject'] },
      'mail1.example.com': { A: ['203.0.113.1'] },
    });
    const codes = result.conditions.map((condition) => condition.code);

    expect(codes).toContain('MTASTS_MISSING');
    expect(codes).toContain('TLSRPT_MISSING');
    expect(codes).toContain('BIMI_MISSING');
  });
});

describe('healthCheck — spoofability follows the effective policy', () => {
  const withDmarc = (record: string): MockZone => ({
    ...healthy,
    '_dmarc.example.com': { TXT: [record] },
  });

  it('is spoofable at p=none however good the SPF is', async () => {
    const { result } = await run(withDmarc('v=DMARC1; p=none; rua=mailto:d@example.com'));
    expect(result.spoofability.verdict).toBe('SPOOFABLE');
  });

  it('is partial at p=quarantine', async () => {
    const { result } = await run(withDmarc('v=DMARC1; p=quarantine; rua=mailto:d@example.com'));
    expect(result.spoofability.verdict).toBe('PARTIAL');
  });

  it('is spoofable at p=reject when test mode is on', async () => {
    // The record says reject. Receivers apply none. This is the case that
    // makes a domain owner certain they are protected when they are not.
    const { result } = await run(withDmarc('v=DMARC1; p=reject; t=y; rua=mailto:d@example.com'));

    expect(result.dmarc.appliedPolicy).toBe('reject');
    expect(result.dmarc.effectivePolicy).toBe('none');
    expect(result.spoofability.verdict).toBe('SPOOFABLE');
    expect(result.spoofability.reasons.join(' ')).toContain('t=y');
  });
});

describe('healthCheck — the subrequest budget', () => {
  it('never exceeds what a Cloudflare Worker request allows', async () => {
    // 50 subrequests is the hard limit for the whole request.
    const { result } = await run(healthy);
    expect(result.meta.queriesUsed).toBeLessThanOrEqual(46);
    expect(result.meta.partial).toBe(false);
  });

  it('stays inside the budget even with a hostile SPF chain', async () => {
    const zone: MockZone = { ...naked };
    let record = 'v=spf1';
    for (let i = 0; i < 30; i += 1) {
      record += ` include:v${i}.example.net`;
      zone[`v${i}.example.net`] = {
        TXT: [`v=spf1 include:w${i}.example.net ip4:198.51.100.0/24 -all`],
      };
      zone[`w${i}.example.net`] = { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] };
    }
    zone['example.com'] = { ...zone['example.com'], TXT: [`${record} -all`] };

    const { result, mock } = await run(zone);

    expect(mock.calls.length).toBeLessThanOrEqual(46);
    expect(result.meta.partial).toBe(true);
    // Over the limit is still reported, from a count we know is a floor.
    expect(result.conditions.map((c) => c.code)).toContain('SPF_LOOKUP_LIMIT_EXCEEDED');
  });

  it('shares lookups between engines rather than repeating them', async () => {
    const { result, mock } = await run(healthy);
    const apexTxt = mock.calls.filter((c) => c.name === 'example.com' && c.type === 'TXT');
    expect(apexTxt).toHaveLength(1);
    expect(result.meta.queriesUsed).toBe(mock.calls.length);
  });

  it('doubles apex lookups only when verification is on', async () => {
    const { mock } = await run(healthy, { verify: true });
    const apexTxt = mock.calls.filter((c) => c.name === 'example.com' && c.type === 'TXT');
    expect(apexTxt).toHaveLength(2);
  });
});

describe('healthCheck — partial results', () => {
  it('still produces a chart when DNS is failing', async () => {
    const mock = createMockDoh(healthy, { fail: () => 'TIMEOUT' });
    const result = await healthCheck('example.com', {
      fetchImpl: mock.fetch,
      timeoutMs: 10,
      verify: false,
    });

    expect(result.conditions.map((c) => c.code)).toContain('RESOLVER_TIMEOUT');
    expect(result.conditions.map((c) => c.code)).not.toContain('SPF_RECORD_MISSING');
    expect(result.records).toHaveLength(10);
    expect(result.vitals.score).toBeGreaterThan(0);
  });

  it('reports timing and the domain it actually checked', async () => {
    const { result } = await run(healthy, {});
    expect(result.domain).toBe('example.com');
    expect(result.checkedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(result.meta.durationMs).toBeGreaterThanOrEqual(0);
  });
});

/**
 * A domain nobody has registered.
 *
 * This is the case that exposed the scoring model. `abcdhsv3648193.com` came
 * back at 39 out of 100 with seven of its ten record cards showing a green dot,
 * and 39 was not a measurement: it was the spoofable ceiling clamping a
 * weighted total of 64. Underneath, "would you find out if something went
 * wrong?" had scored full marks, because there was no DMARC record for a
 * missing reporting address to be a fault in.
 */
describe('a domain that does not exist', () => {
  const nowhere: MockZone = {};

  it('scores zero rather than the ceiling', async () => {
    const mock = createMockDoh(nowhere);
    const result = await healthCheck('abcdhsv3648193.com', { fetchImpl: mock.fetch });

    expect(result.vitals.score).toBe(0);
    expect(result.vitals.band).toBe('CRITICAL');
  });

  it('never tells it its transport security is not needed', async () => {
    // "Not published, and not needed, this domain receives no mail" is a
    // sentence that reads as approval, and it was being said about a zone that
    // is not there.
    const mock = createMockDoh(nowhere);
    const result = await healthCheck('abcdhsv3648193.com', { fetchImpl: mock.fetch });

    for (const record of result.records) {
      expect(record.summary).not.toContain('not needed');
    }
    const mtasts = result.records.find((r) => r.record === 'MTASTS');
    expect(mtasts?.summary).toBe('Not checked, this domain does not resolve');
  });

  it('says the domain does not resolve', async () => {
    const mock = createMockDoh(nowhere);
    const result = await healthCheck('abcdhsv3648193.com', { fetchImpl: mock.fetch });

    expect(result.conditions.map((c) => c.code)).toContain('DOMAIN_NXDOMAIN');
  });
});
