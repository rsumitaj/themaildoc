import { describe, expect, it } from 'vitest';
import { DohResolver } from '@maildoc/resolver';
import { createMockDoh, type MockZone } from '@maildoc/resolver/testing';
import { evaluateSpf, type SpfEvaluateOptions } from '../src/index.js';

/**
 * check_host() against mock DNS — RFC 7208 §4.
 *
 * Every case here is a decision a real receiver makes, and the expected result
 * is what the RFC requires rather than what would be convenient. If this file
 * is honest, the answer we give somebody holding a bounce message is the answer
 * the server that bounced it gave.
 */

async function run(
  zone: MockZone,
  ip: string,
  options: SpfEvaluateOptions & { domain?: string; budget?: number } = {},
) {
  const { domain = 'example.com', budget, ...evalOptions } = options;
  const mock = createMockDoh(zone);
  const resolver = new DohResolver({
    fetchImpl: mock.fetch,
    timeoutMs: 20,
    ...(budget === undefined ? {} : { budget }),
  });
  const evaluation = await evaluateSpf(domain, ip, resolver, evalOptions);
  return { evaluation, mock, terms: evaluation.trace.map((step) => step.term) };
}

describe('the four qualifiers', () => {
  const zone: MockZone = {
    'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] },
  };

  it('passes an address inside an ip4 range', async () => {
    const { evaluation } = await run(zone, '203.0.113.9');

    expect(evaluation.result).toBe('pass');
    expect(evaluation.matched?.term).toBe('ip4:203.0.113.0/24');
    expect(evaluation.lookups).toBe(0);
  });

  it('fails an address outside it, because the record ends in -all', async () => {
    const { evaluation } = await run(zone, '198.51.100.9');

    expect(evaluation.result).toBe('fail');
    expect(evaluation.matched?.term).toBe('-all');
  });

  it('softfails when the record ends in ~all', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 ~all'] } },
      '198.51.100.9',
    );
    expect(evaluation.result).toBe('softfail');
  });

  it('is neutral when the record ends in ?all', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 ?all'] } },
      '198.51.100.9',
    );
    expect(evaluation.result).toBe('neutral');
  });

  it('is neutral when there is no all mechanism at all', async () => {
    // §4.7: the default result when nothing matches and nothing redirects.
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24'] } },
      '198.51.100.9',
    );
    expect(evaluation.result).toBe('neutral');
  });

  it('reports none when the domain publishes no SPF record', async () => {
    const { evaluation } = await run({ 'example.com': { A: ['203.0.113.1'] } }, '203.0.113.1');
    expect(evaluation.result).toBe('none');
  });
});

describe('the first match wins', () => {
  it('stops at the first matching mechanism and never reads the rest', async () => {
    // §4.6.2. A record that authorises then denies the same address authorises
    // it, and a checker that evaluates every term would say the opposite.
    const { evaluation, terms } = await run(
      { 'example.com': { TXT: ['v=spf1 ip4:203.0.113.9 -ip4:203.0.113.0/24 -all'] } },
      '203.0.113.9',
    );

    expect(evaluation.result).toBe('pass');
    expect(terms).toEqual(['ip4:203.0.113.9']);
  });

  it('carries the qualifier of the mechanism that matched, not the one on all', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 -ip4:203.0.113.0/24 +all'] } },
      '203.0.113.9',
    );
    expect(evaluation.result).toBe('fail');
  });
});

describe('include, which most checkers get backwards', () => {
  const zone: MockZone = {
    'example.com': { TXT: ['v=spf1 include:vendor.test include:other.test -all'] },
    'vendor.test': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
    'other.test': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] },
  };

  it('matches when the recursion passes', async () => {
    const { evaluation } = await run(zone, '198.51.100.7');

    expect(evaluation.result).toBe('pass');
    expect(evaluation.matched?.term).toBe('include:vendor.test');
  });

  it('moves on to the next term when the recursion fails', async () => {
    // §5.2: an include that does not pass is not a fail, it is a no-match. A
    // checker that returns the inner fail turns every multi-vendor domain into
    // a fail on its second vendor.
    const { evaluation } = await run(zone, '203.0.113.7');

    expect(evaluation.result).toBe('pass');
    expect(evaluation.matched?.term).toBe('include:other.test');
  });

  it('falls through to all when no include passes', async () => {
    const { evaluation } = await run(zone, '192.0.2.7');

    expect(evaluation.result).toBe('fail');
    expect(evaluation.matched?.term).toBe('-all');
  });

  it('is a permanent error when the include target has no SPF record', async () => {
    // §5.2 again: none inside an include becomes permerror outside it.
    const { evaluation } = await run(
      {
        'example.com': { TXT: ['v=spf1 include:nothing.test -all'] },
        'nothing.test': { A: ['203.0.113.1'] },
      },
      '203.0.113.1',
    );
    expect(evaluation.result).toBe('permerror');
  });

  it('catches a chain that loops instead of walking it forever', async () => {
    const { evaluation } = await run(
      {
        'example.com': { TXT: ['v=spf1 include:loop.test -all'] },
        'loop.test': { TXT: ['v=spf1 include:example.com -all'] },
      },
      '203.0.113.1',
    );
    expect(evaluation.result).toBe('permerror');
  });
});

describe('a and mx', () => {
  const zone: MockZone = {
    'example.com': {
      TXT: ['v=spf1 a mx -all'],
      A: ['203.0.113.10'],
      MX: ['10 mail.example.com'],
    },
    'mail.example.com': { A: ['198.51.100.20'] },
  };

  it('matches the domain’s own address record', async () => {
    const { evaluation } = await run(zone, '203.0.113.10');

    expect(evaluation.result).toBe('pass');
    expect(evaluation.matched?.term).toBe('a');
  });

  it('matches an address behind an MX host', async () => {
    const { evaluation } = await run(zone, '198.51.100.20');

    expect(evaluation.result).toBe('pass');
    expect(evaluation.matched?.term).toBe('mx');
  });

  it('applies the CIDR the mechanism carries', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 a/24 -all'], A: ['203.0.113.10'] } },
      '203.0.113.200',
    );
    expect(evaluation.result).toBe('pass');
  });

  it('does not match a neighbour when there is no CIDR', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 a -all'], A: ['203.0.113.10'] } },
      '203.0.113.11',
    );
    expect(evaluation.result).toBe('fail');
  });

  it('charges one lookup for mx however many hosts it examines', async () => {
    // §4.6.4: the mechanism costs one lookup; resolving its names is capped at
    // ten rather than charged. Counting each host would put ordinary domains
    // over the limit and report a permanent error that receivers do not.
    const { evaluation } = await run(
      {
        'example.com': {
          TXT: ['v=spf1 mx -all'],
          MX: ['10 a.example.com', '20 b.example.com', '30 c.example.com'],
        },
        'a.example.com': { A: ['203.0.113.1'] },
        'b.example.com': { A: ['203.0.113.2'] },
        'c.example.com': { A: ['203.0.113.3'] },
      },
      '203.0.113.3',
    );

    expect(evaluation.result).toBe('pass');
    expect(evaluation.lookups).toBe(1);
  });
});

describe('exists, evaluated for this connection', () => {
  it('expands %{i} and matches when the name is published', async () => {
    // The whole point of an IP check. Nothing that only reads a record can say
    // what this mechanism does, because the name is different per sender.
    const { evaluation } = await run(
      {
        'example.com': { TXT: ['v=spf1 exists:%{i}._spf.example.com -all'] },
        '203.0.113.9._spf.example.com': { A: ['127.0.0.1'] },
      },
      '203.0.113.9',
    );

    expect(evaluation.result).toBe('pass');
    expect(evaluation.matched?.term).toBe('exists:%{i}._spf.example.com');
  });

  it('does not match when the expanded name does not exist', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 exists:%{i}._spf.example.com -all'] } },
      '203.0.113.9',
    );
    expect(evaluation.result).toBe('fail');
  });

  it('expands the sender macros too', async () => {
    const { evaluation } = await run(
      {
        'example.com': { TXT: ['v=spf1 exists:%{l}.%{o}._spf.example.com -all'] },
        'alice.example.com._spf.example.com': { A: ['127.0.0.1'] },
      },
      '203.0.113.9',
      { sender: 'alice@example.com' },
    );
    expect(evaluation.result).toBe('pass');
  });
});

describe('the limits are permanent errors, not warnings', () => {
  it('stops at ten lookups', async () => {
    // §4.6.4. This is the case checkers report as "your record is long" while
    // receivers are refusing the mail outright.
    const zone: MockZone = {
      'example.com': {
        TXT: [
          'v=spf1 include:a.test include:b.test include:c.test include:d.test include:e.test include:f.test include:g.test include:h.test include:i.test include:j.test include:k.test -all',
        ],
      },
    };
    for (const letter of 'abcdefghijk') {
      zone[`${letter}.test`] = { TXT: ['v=spf1 ip4:192.0.2.1 -all'] };
    }

    const { evaluation } = await run(zone, '203.0.113.9', { budget: 40 });

    expect(evaluation.result).toBe('permerror');
    expect(evaluation.lookups).toBe(10);
  });

  it('allows exactly ten, because ten is the limit and not one less', async () => {
    // §4.6.4 caps the terms at ten; the eleventh is the error. A checker that
    // errors at the tenth condemns records that receivers evaluate happily.
    const zone: MockZone = {
      'example.com': {
        TXT: [
          'v=spf1 include:a.test include:b.test include:c.test include:d.test include:e.test include:f.test include:g.test include:h.test include:i.test include:j.test ip4:203.0.113.9 -all',
        ],
      },
    };
    for (const letter of 'abcdefghij') {
      zone[`${letter}.test`] = { TXT: ['v=spf1 ip4:192.0.2.1 -all'] };
    }

    const { evaluation } = await run(zone, '203.0.113.9', { budget: 40 });

    expect(evaluation.lookups).toBe(10);
    expect(evaluation.result).toBe('pass');
  });

  it('fails a domain’s own sender once the record is over the limit', async () => {
    // The consequence worth stating plainly: past ten lookups SPF fails for
    // everybody, including the servers the record was written to authorise.
    // The ip4 that would have passed sits after the eleventh include and is
    // never reached, which is exactly what happens on the receiving end.
    const zone: MockZone = {
      'example.com': {
        TXT: [
          'v=spf1 include:a.test include:b.test include:c.test include:d.test include:e.test include:f.test include:g.test include:h.test include:i.test include:j.test include:k.test ip4:203.0.113.9 -all',
        ],
      },
    };
    for (const letter of 'abcdefghijk') {
      zone[`${letter}.test`] = { TXT: ['v=spf1 ip4:192.0.2.1 -all'] };
    }

    const { evaluation } = await run(zone, '203.0.113.9', { budget: 40 });
    expect(evaluation.result).toBe('permerror');
  });

  it('treats two SPF records at one name as a permanent error', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip4:203.0.113.9 -all', 'v=spf1 -all'] } },
      '203.0.113.9',
    );
    expect(evaluation.result).toBe('permerror');
  });
});

describe('redirect', () => {
  it('hands the answer to the target when nothing matched', async () => {
    const { evaluation } = await run(
      {
        'example.com': { TXT: ['v=spf1 ip4:192.0.2.0/24 redirect=policy.test'] },
        'policy.test': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] },
      },
      '203.0.113.9',
    );
    expect(evaluation.result).toBe('pass');
  });

  it('is ignored when the record also has an all mechanism', async () => {
    // §6.1. A receiver reaches `all`, which always matches, so the redirect is
    // unreachable. Showing it in the trace is how somebody finds out why the
    // record they edited did nothing.
    const { evaluation, terms } = await run(
      {
        'example.com': { TXT: ['v=spf1 ~all redirect=policy.test'] },
        'policy.test': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] },
      },
      '203.0.113.9',
    );

    expect(evaluation.result).toBe('softfail');
    expect(terms).not.toContain('redirect=policy.test');
  });

  it('is a permanent error when the target publishes no record', async () => {
    const { evaluation } = await run(
      {
        'example.com': { TXT: ['v=spf1 redirect=policy.test'] },
        'policy.test': { A: ['203.0.113.1'] },
      },
      '203.0.113.9',
    );
    expect(evaluation.result).toBe('permerror');
  });
});

describe('IPv6, and the addresses that look like both', () => {
  it('matches an ip6 range', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip6:2001:db8::/32 -all'] } },
      '2001:db8:1234::9',
    );
    expect(evaluation.result).toBe('pass');
  });

  it('never matches an IPv4 sender against an ip6 range', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip6:2001:db8::/32 -all'] } },
      '203.0.113.9',
    );
    expect(evaluation.result).toBe('fail');
  });

  it('treats an IPv4-mapped address as the IPv4 sender it is', async () => {
    // A dual-stack receiver reports ::ffff:203.0.113.9 for a client that
    // connected over IPv4, and matches it against ip4:. Treating it as IPv6
    // would report "not authorised" for a sender that is plainly listed.
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] } },
      '::ffff:203.0.113.9',
    );

    expect(evaluation.result).toBe('pass');
    expect(evaluation.ipVersion).toBe(4);
    expect(evaluation.ip).toBe('203.0.113.9');
  });

  it('uses the //64 half of a dual-CIDR mechanism for an IPv6 sender', async () => {
    const { evaluation } = await run(
      {
        'example.com': { TXT: ['v=spf1 a/24//64 -all'], AAAA: ['2001:db8:0:1::5'] },
      },
      '2001:db8:0:1::99',
    );
    expect(evaluation.result).toBe('pass');
  });
});

describe('what it refuses to guess', () => {
  it('is a temporary error when DNS does not answer', async () => {
    // Reporting "not authorised" for a name we failed to resolve would be a lie
    // in the most expensive direction: somebody would remove a sender that was
    // authorised all along.
    const { evaluation } = await run(
      {
        'example.com': { TXT: ['v=spf1 include:broken.test -all'] },
        'broken.test': { TXT: { status: 'SERVFAIL' } },
      },
      '203.0.113.9',
    );

    expect(evaluation.result).toBe('temperror');
    expect(evaluation.complete).toBe(false);
  });

  it('rejects input that is not an address at all', async () => {
    const { evaluation } = await run({ 'example.com': { TXT: ['v=spf1 -all'] } }, 'not-an-ip');

    expect(evaluation.result).toBe('permerror');
    expect(evaluation.queriesUsed).toBe(0);
  });
});

describe('the trace explains the answer', () => {
  it('records every term considered, in the order a receiver considered them', async () => {
    const { evaluation, terms } = await run(
      {
        'example.com': { TXT: ['v=spf1 ip4:192.0.2.0/24 include:vendor.test ~all'] },
        'vendor.test': { TXT: ['v=spf1 ip4:198.51.100.0/24 -all'] },
      },
      '198.51.100.7',
    );

    expect(terms).toEqual(['ip4:192.0.2.0/24', 'include:vendor.test', 'ip4:198.51.100.0/24']);
    expect(evaluation.trace[0]?.outcome).toBe('no-match');
    expect(evaluation.trace[1]?.outcome).toBe('match');
    expect(evaluation.trace[2]?.depth).toBe(1);
  });

  it('says which mechanism decided it, not just the answer', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] } },
      '203.0.113.9',
    );

    expect(evaluation.summary).toContain('ip4:203.0.113.0/24');
    expect(evaluation.summary).toContain('203.0.113.9');
  });
});

/**
 * Which permanent errors condemn the record, and which are about one sender.
 *
 * "permerror" covers two very different situations. A record over the lookup
 * limit is broken for everybody, including the domain's own mail server, and
 * the fix is urgent. A record that ran out of void lookups is usually broken
 * only for the address being checked: records built on `exists:` with macros
 * perform a lookup per sender by design, and empty answers are the expected
 * outcome for an address the domain never authorised.
 *
 * zoom.us reads as a permanent error for a TEST-NET address and delivers
 * perfectly well for its real senders. Telling somebody their record cannot be
 * evaluated would have them rewrite a working one.
 */
describe('telling the two permanent errors apart', () => {
  it('condemns the record when it is over the lookup limit', async () => {
    const zone: MockZone = {
      'example.com': {
        TXT: [
          'v=spf1 include:a.test include:b.test include:c.test include:d.test include:e.test include:f.test include:g.test include:h.test include:i.test include:j.test include:k.test -all',
        ],
      },
    };
    for (const letter of 'abcdefghijk') {
      zone[`${letter}.test`] = { TXT: ['v=spf1 ip4:192.0.2.1 -all'] };
    }

    const { evaluation } = await run(zone, '203.0.113.9', { budget: 40 });

    expect(evaluation.result).toBe('permerror');
    expect(evaluation.cause).toBe('LOOKUP_LIMIT');
    expect(evaluation.breaksEverySender).toBe(true);
    expect(evaluation.summary).toContain('every sender');
  });

  it('blames the sender, not the record, when the void limit is what fired', async () => {
    // Three `exists:` lookups that answer for a real sender and are empty for
    // this one. The record is doing exactly what it was written to do.
    const { evaluation } = await run(
      {
        'example.com': {
          TXT: [
            'v=spf1 exists:%{i}.a.test exists:%{i}.b.test exists:%{i}.c.test ip4:203.0.113.9 -all',
          ],
        },
      },
      '198.51.100.7',
    );

    expect(evaluation.result).toBe('permerror');
    expect(evaluation.cause).toBe('VOID_LIMIT');
    expect(evaluation.breaksEverySender).toBe(false);
    expect(evaluation.summary).toContain('this address');
    expect(evaluation.summary).not.toContain('every sender');
  });

  it('does not fire the void limit for a sender the record does answer for', async () => {
    // The same record, the same three mechanisms, an address it knows.
    const { evaluation } = await run(
      {
        'example.com': {
          TXT: ['v=spf1 exists:%{i}.a.test exists:%{i}.b.test exists:%{i}.c.test -all'],
        },
        '198.51.100.7.a.test': { A: ['127.0.0.1'] },
      },
      '198.51.100.7',
    );

    expect(evaluation.result).toBe('pass');
    expect(evaluation.cause).toBeNull();
  });

  it('names two records at one name as the cause', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip4:203.0.113.9 -all', 'v=spf1 -all'] } },
      '203.0.113.9',
    );

    expect(evaluation.cause).toBe('MULTIPLE_RECORDS');
    expect(evaluation.breaksEverySender).toBe(true);
  });

  it('names a missing include target as the cause', async () => {
    const { evaluation } = await run(
      {
        'example.com': { TXT: ['v=spf1 include:nothing.test -all'] },
        'nothing.test': { A: ['203.0.113.1'] },
      },
      '203.0.113.1',
    );

    expect(evaluation.cause).toBe('MISSING_TARGET');
    expect(evaluation.breaksEverySender).toBe(true);
  });

  it('leaves the cause unset when nothing went wrong', async () => {
    const { evaluation } = await run(
      { 'example.com': { TXT: ['v=spf1 ip4:203.0.113.0/24 -all'] } },
      '203.0.113.9',
    );

    expect(evaluation.cause).toBeNull();
    expect(evaluation.breaksEverySender).toBe(false);
  });

  it('attributes the void limit to itself rather than to the next term along', async () => {
    // `-all` did not cause this, and a row saying so beside it reads as a fault
    // in a mechanism that is doing nothing wrong.
    const { evaluation } = await run(
      {
        'example.com': {
          TXT: ['v=spf1 exists:%{i}.a.test exists:%{i}.b.test exists:%{i}.c.test -all'],
        },
      },
      '198.51.100.7',
    );

    const error = evaluation.trace.find((step) => step.outcome === 'error');
    expect(error?.term).toBe('3 empty lookups');
  });
});
