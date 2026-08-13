import { describe, expect, it } from 'vitest';
import { DohResolver } from '@maildoc/resolver';
import { createMockDoh, type MockZone } from '@maildoc/resolver/testing';
import {
  analyzeBimi,
  analyzeCaa,
  analyzeMtaSts,
  analyzePtr,
  analyzeTlsRpt,
  parsePolicy,
  policyCoversHost,
  reverseName,
} from '../src/index.js';

const resolverFor = (zone: MockZone) => {
  const mock = createMockDoh(zone);
  return { mock, resolver: new DohResolver({ fetchImpl: mock.fetch, timeoutMs: 20, budget: 40 }) };
};

const codesOf = (analysis: { conditions: Array<{ code: string }> }) =>
  analysis.conditions.map((condition) => condition.code);

/** A stand-in for the policy web server. */
const policyServer = (
  body: string,
  init: { status?: number } = {},
): ((url: string) => Promise<Response>) => {
  return async (url: string) => {
    if (!url.includes('/.well-known/mta-sts.txt')) throw new Error('unexpected url');
    return new Response(body, { status: init.status ?? 200 });
  };
};

const VALID_POLICY = 'version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 604800\n';

describe('MTA-STS', () => {
  const announced: MockZone = {
    '_mta-sts.example.com': { TXT: ['v=STSv1; id=20260101000000'] },
  };

  it('reports a domain with no policy at all', async () => {
    const { resolver } = resolverFor({});
    const analysis = await analyzeMtaSts('example.com', resolver, { fetchPolicy: false });
    expect(codesOf(analysis)).toEqual(['MTASTS_MISSING']);
    expect(analysis.announced).toBe(false);
  });

  it('accepts a well-formed announcement and policy', async () => {
    const { resolver } = resolverFor(announced);
    const analysis = await analyzeMtaSts('example.com', resolver, {
      fetchImpl: policyServer(VALID_POLICY) as never,
      mxHosts: ['mail.example.com'],
    });

    expect(codesOf(analysis)).toEqual([]);
    expect(analysis.policy?.mode).toBe('enforce');
    expect(analysis.policyFetched).toBe(true);
  });

  it('refuses to follow a redirect, as senders must not', async () => {
    // RFC 8461 §3.3 — a policy behind a redirect does not exist.
    const { resolver } = resolverFor(announced);
    const analysis = await analyzeMtaSts('example.com', resolver, {
      fetchImpl: (async () => new Response('', { status: 301 })) as never,
    });

    expect(codesOf(analysis)).toContain('MTASTS_POLICY_REDIRECT');
    expect(codesOf(analysis)).not.toContain('MTASTS_POLICY_UNREACHABLE');
  });

  it('reports a policy file that is not served', async () => {
    const { resolver } = resolverFor(announced);
    const analysis = await analyzeMtaSts('example.com', resolver, {
      fetchImpl: (async () => new Response('nope', { status: 404 })) as never,
    });
    expect(codesOf(analysis)).toContain('MTASTS_POLICY_UNREACHABLE');
  });

  it('treats an invalid certificate as unreachable, because senders do', async () => {
    const { resolver } = resolverFor(announced);
    const analysis = await analyzeMtaSts('example.com', resolver, {
      fetchImpl: (async () => {
        throw new TypeError('certificate has expired');
      }) as never,
    });
    expect(codesOf(analysis)).toContain('MTASTS_POLICY_UNREACHABLE');
  });

  it('flags testing mode as a step, not a fault', async () => {
    const { resolver } = resolverFor(announced);
    const analysis = await analyzeMtaSts('example.com', resolver, {
      fetchImpl: policyServer(VALID_POLICY.replace('enforce', 'testing')) as never,
      mxHosts: ['mail.example.com'],
    });

    expect(codesOf(analysis)).toEqual(['MTASTS_MODE_TESTING']);
    // Amber, not green. Testing mode is the right first step and it still
    // protects nothing on its own, which is why it costs eight points. A green
    // dot beside a finding the same page is charging for was the interface
    // disagreeing with its own arithmetic.
    expect(analysis.status).toBe('ATTENTION');
  });

  it('catches a policy that omits a live mail server', async () => {
    const { resolver } = resolverFor(announced);
    const analysis = await analyzeMtaSts('example.com', resolver, {
      fetchImpl: policyServer(VALID_POLICY) as never,
      mxHosts: ['mail.example.com', 'backup.example.com'],
    });

    expect(codesOf(analysis)).toContain('MTASTS_MX_MISMATCH');
    expect(analysis.conditions[0]?.severity).toBe('CRITICAL');
    expect(analysis.conditions[0]?.why).toContain('backup.example.com');
  });

  it('flags a max_age outside the usable range', async () => {
    const { resolver } = resolverFor(announced);
    const analysis = await analyzeMtaSts('example.com', resolver, {
      fetchImpl: policyServer(VALID_POLICY.replace('604800', '60')) as never,
      mxHosts: ['mail.example.com'],
    });
    expect(codesOf(analysis)).toContain('MTASTS_MAXAGE_INVALID');
  });

  it('flags a malformed announcement', async () => {
    const { resolver } = resolverFor({ '_mta-sts.example.com': { TXT: ['v=STSv1'] } });
    const analysis = await analyzeMtaSts('example.com', resolver, { fetchPolicy: false });
    expect(codesOf(analysis)).toContain('MTASTS_TXT_INVALID');
  });
});

describe('MTA-STS policy parsing', () => {
  it('reads the four keys that matter', () => {
    const policy = parsePolicy(VALID_POLICY);
    expect(policy).toEqual({
      version: 'STSv1',
      mode: 'enforce',
      mx: ['mail.example.com'],
      maxAge: 604800,
    });
  });

  it('collects every mx line', () => {
    const policy = parsePolicy('version: STSv1\nmode: enforce\nmx: a.example.com\nmx: b.example.com\nmax_age: 604800');
    expect(policy.mx).toEqual(['a.example.com', 'b.example.com']);
  });

  it('matches a wildcard only against the leftmost label', () => {
    expect(policyCoversHost(['*.mail.example.com'], 'mx1.mail.example.com')).toBe(true);
    expect(policyCoversHost(['*.mail.example.com'], 'a.b.mail.example.com')).toBe(false);
    expect(policyCoversHost(['*.mail.example.com'], 'mail.example.com')).toBe(false);
    expect(policyCoversHost(['mail.example.com'], 'MAIL.example.com.')).toBe(true);
  });
});

describe('TLS-RPT', () => {
  it('reports a missing record as a gap in visibility', async () => {
    const { resolver } = resolverFor({});
    const analysis = await analyzeTlsRpt('example.com', resolver);
    expect(codesOf(analysis)).toEqual(['TLSRPT_MISSING']);
    expect(analysis.conditions[0]?.severity).toBe('LOW');
  });

  it('accepts a valid record', async () => {
    const { resolver } = resolverFor({
      '_smtp._tls.example.com': { TXT: ['v=TLSRPTv1; rua=mailto:tls@example.com'] },
    });
    const analysis = await analyzeTlsRpt('example.com', resolver);
    expect(codesOf(analysis)).toEqual([]);
    expect(analysis.destinations).toEqual(['mailto:tls@example.com']);
  });

  it('accepts an https destination', async () => {
    const { resolver } = resolverFor({
      '_smtp._tls.example.com': { TXT: ['v=TLSRPTv1; rua=https://reports.example.com/tls'] },
    });
    expect(codesOf(await analyzeTlsRpt('example.com', resolver))).toEqual([]);
  });

  it('rejects a wrong version string, which is case-sensitive', async () => {
    const { resolver } = resolverFor({
      '_smtp._tls.example.com': { TXT: ['v=tlsrptv1; rua=mailto:tls@example.com'] },
    });
    expect(codesOf(await analyzeTlsRpt('example.com', resolver))).toContain('TLSRPT_INVALID');
  });

  it('flags an unusable destination', async () => {
    const { resolver } = resolverFor({
      '_smtp._tls.example.com': { TXT: ['v=TLSRPTv1; rua=tls@example.com'] },
    });
    expect(codesOf(await analyzeTlsRpt('example.com', resolver))).toContain('TLSRPT_RUA_INVALID');
  });
});

describe('BIMI', () => {
  it('treats a missing record as optional, not a fault', async () => {
    const { resolver } = resolverFor({});
    const analysis = await analyzeBimi('example.com', resolver, { dmarcPolicy: 'reject' });
    expect(codesOf(analysis)).toEqual(['BIMI_MISSING']);
    expect(analysis.conditions[0]?.severity).toBe('INFO');
  });

  it('accepts a complete record on an enforcing domain', async () => {
    const { resolver } = resolverFor({
      'default._bimi.example.com': {
        TXT: ['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'],
      },
    });
    const analysis = await analyzeBimi('example.com', resolver, { dmarcPolicy: 'reject' });
    expect(codesOf(analysis)).toEqual([]);
    expect(analysis.logo).toBe('https://example.com/logo.svg');
  });

  it('says plainly that BIMI does nothing without DMARC enforcement', async () => {
    const { resolver } = resolverFor({
      'default._bimi.example.com': {
        TXT: ['v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem'],
      },
    });
    const analysis = await analyzeBimi('example.com', resolver, { dmarcPolicy: 'none' });
    expect(codesOf(analysis)).toContain('BIMI_DMARC_NOT_ENFORCED');
    expect(analysis.conditions[0]?.why).toContain('p=none');
  });

  it('flags a logo that is not on HTTPS', async () => {
    const { resolver } = resolverFor({
      'default._bimi.example.com': { TXT: ['v=BIMI1; l=http://example.com/logo.svg'] },
    });
    const analysis = await analyzeBimi('example.com', resolver, { dmarcPolicy: 'reject' });
    expect(codesOf(analysis)).toContain('BIMI_LOGO_INSECURE');
  });

  it('recognises a record that declines to display', async () => {
    const { resolver } = resolverFor({
      'default._bimi.example.com': { TXT: ['v=BIMI1; l=;'] },
    });
    const analysis = await analyzeBimi('example.com', resolver, { dmarcPolicy: 'reject' });
    expect(analysis.declined).toBe(true);
    expect(codesOf(analysis)).toEqual(['BIMI_DECLINED']);
  });

  it('notes a missing certificate', async () => {
    const { resolver } = resolverFor({
      'default._bimi.example.com': { TXT: ['v=BIMI1; l=https://example.com/logo.svg'] },
    });
    expect(codesOf(await analyzeBimi('example.com', resolver, { dmarcPolicy: 'reject' }))).toContain(
      'BIMI_VMC_MISSING',
    );
  });

  it('does not correct a wrong version, as receivers must not', async () => {
    const { resolver } = resolverFor({
      'default._bimi.example.com': { TXT: ['v=bimi1; l=https://example.com/logo.svg'] },
    });
    expect(codesOf(await analyzeBimi('example.com', resolver, { dmarcPolicy: 'reject' }))).toContain(
      'BIMI_SYNTAX',
    );
  });
});

describe('CAA', () => {
  it('notes an absent record as an open door, gently', async () => {
    const { resolver } = resolverFor({});
    const analysis = await analyzeCaa('example.com', resolver);
    expect(codesOf(analysis)).toEqual(['CAA_MISSING']);
    expect(analysis.conditions[0]?.severity).toBe('INFO');
  });

  it('reads authorised issuers', async () => {
    const { resolver } = resolverFor({
      'example.com': { CAA: ['0 issue "letsencrypt.org"', '0 issuewild "digicert.com"'] },
    });
    const analysis = await analyzeCaa('example.com', resolver);

    expect(analysis.issuers).toEqual(['letsencrypt.org']);
    expect(analysis.wildcardIssuers).toEqual(['digicert.com']);
    expect(codesOf(analysis)).toEqual([]);
  });

  it('recognises a deliberate lock on all issuance', async () => {
    const { resolver } = resolverFor({ 'example.com': { CAA: ['0 issue ";"'] } });
    const analysis = await analyzeCaa('example.com', resolver);
    expect(analysis.forbidsAll).toBe(true);
    expect(codesOf(analysis)).toEqual(['CAA_FORBIDS_ALL']);
  });

  it('flags a property that is in no registry', async () => {
    const { resolver } = resolverFor({ 'example.com': { CAA: ['0 notaproperty "example.net"'] } });
    expect(codesOf(await analyzeCaa('example.com', resolver))).toContain('CAA_SYNTAX');
  });

  it('accepts every property tag IANA has registered', async () => {
    // This test previously used `issuemail` as its example of an invalid
    // property. It is RFC 9495, and the registry has grown well past the three
    // tags RFC 8659 defines: microsoft.com's valid `contactemail` record was
    // being reported as a fifteen-point fault.
    for (const property of [
      'iodef',
      'contactemail',
      'contactphone',
      'issuemail',
      'issuewildmail',
      'issuevmc',
      'accounturi',
      'validationmethods',
    ]) {
      const { resolver } = resolverFor({
        'example.com': { CAA: ['0 issue "letsencrypt.org"', `0 ${property} "whatever"`] },
      });
      expect(codesOf(await analyzeCaa('example.com', resolver)), property).toEqual([]);
    }
  });

  it('ignores iodef, which is valid', async () => {
    const { resolver } = resolverFor({
      'example.com': { CAA: ['0 issue "letsencrypt.org"', '0 iodef "mailto:ca@example.com"'] },
    });
    expect(codesOf(await analyzeCaa('example.com', resolver))).toEqual([]);
  });
});

describe('PTR / FCrDNS', () => {
  it('builds the reverse name correctly', () => {
    expect(reverseName('203.0.113.10')).toBe('10.113.0.203.in-addr.arpa');
  });

  it('is satisfied when reverse and forward agree', async () => {
    const { resolver } = resolverFor({
      '10.113.0.203.in-addr.arpa': { PTR: ['mail.example.com.'] },
      'mail.example.com': { A: ['203.0.113.10'] },
    });
    const analysis = await analyzePtr('example.com', resolver, { addresses: ['203.0.113.10'] });

    expect(codesOf(analysis)).toEqual([]);
    expect(analysis.checked[0]?.forwardConfirmed).toBe(true);
  });

  it('reports a mail server with no reverse DNS', async () => {
    const { resolver } = resolverFor({});
    const analysis = await analyzePtr('example.com', resolver, { addresses: ['203.0.113.10'] });
    expect(codesOf(analysis)).toEqual(['PTR_MISSING']);
  });

  it('reports reverse DNS that does not round-trip', async () => {
    const { resolver } = resolverFor({
      '10.113.0.203.in-addr.arpa': { PTR: ['mail.example.com.'] },
      'mail.example.com': { A: ['198.51.100.1'] },
    });
    const analysis = await analyzePtr('example.com', resolver, { addresses: ['203.0.113.10'] });

    expect(codesOf(analysis)).toContain('FCRDNS_FAIL');
    expect(analysis.checked[0]?.forwardConfirmed).toBe(false);
  });

  it('flags a provider-assigned hostname', async () => {
    const { resolver } = resolverFor({
      '10.113.0.203.in-addr.arpa': { PTR: ['ec2-203-0-113-10.compute.example.net.'] },
      'ec2-203-0-113-10.compute.example.net': { A: ['203.0.113.10'] },
    });
    const analysis = await analyzePtr('example.com', resolver, { addresses: ['203.0.113.10'] });

    expect(codesOf(analysis)).toContain('PTR_GENERIC');
    expect(codesOf(analysis)).not.toContain('FCRDNS_FAIL');
  });

  it('says nothing at all when the domain has no servers of its own', async () => {
    // Everything sent through vendors: their PTRs are their business.
    const { resolver } = resolverFor({});
    const analysis = await analyzePtr('example.com', resolver, { addresses: [] });

    expect(analysis.conditions).toEqual([]);
    expect(analysis.noOwnServers).toBe(true);
  });

  it('caps how many addresses it will spend queries on', async () => {
    const { resolver, mock } = resolverFor({});
    await analyzePtr('example.com', resolver, {
      addresses: ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4'],
      maxAddresses: 2,
    });
    expect(mock.calls.length).toBeLessThanOrEqual(2);
  });
});

describe('policy fetch limits', () => {
  const announced: MockZone = {
    '_mta-sts.example.com': { TXT: ['v=STSv1; id=20260101000000'] },
  };

  it('refuses a body larger than a policy file could be', async () => {
    const huge = `${VALID_POLICY}${'x'.repeat(200_000)}`;
    const { resolver } = resolverFor(announced);
    const analysis = await analyzeMtaSts('example.com', resolver, {
      fetchImpl: policyServer(huge) as never,
      mxHosts: ['mail.example.com'],
    });

    // A sender that cannot read the policy has no policy, which is exactly
    // what we report. The point is that we never hold 200KB to find out.
    expect(codesOf(analysis)).toContain('MTASTS_POLICY_UNREACHABLE');
    expect(analysis.policyText).toBeNull();
  });

  it('refuses on a declared content-length over the ceiling', async () => {
    const { resolver } = resolverFor(announced);
    const analysis = await analyzeMtaSts('example.com', resolver, {
      fetchImpl: (async () =>
        new Response(VALID_POLICY, {
          status: 200,
          headers: { 'content-length': String(10 * 1024 * 1024) },
        })) as never,
      mxHosts: ['mail.example.com'],
    });

    expect(codesOf(analysis)).toContain('MTASTS_POLICY_UNREACHABLE');
    expect(analysis.policyText).toBeNull();
  });
});
