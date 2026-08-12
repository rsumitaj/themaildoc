import { describe, expect, it } from 'vitest';
import {
  createCondition,
  dedupeConditions,
  rollupRecord,
  scoreBreakdown,
  scoreConditions,
  sortConditions,
  vitalsBand,
  vitals,
  worstSeverity,
} from '../src/index.js';

const critical = () => createCondition('SPF_RECORD_MISSING', { domain: 'a.com' });
const high = () => createCondition('SPF_ALL_MISSING', { domain: 'a.com' });
const medium = () => createCondition('SPF_UDP_TRUNCATION_RISK', { count: 470 });
const info = () => createCondition('SPF_SOFTFAIL_ADVISORY', { domain: 'a.com' });

describe('scoreConditions', () => {
  it('starts at 100 for a clean bill of health', () => {
    expect(scoreConditions([])).toBe(100);
  });

  it('costs more the more severe the finding is', () => {
    // These all land in the impersonation pillar, which carries 45 percent, so
    // a 40 point finding removes 18 from the total rather than 40. The ordering
    // is what matters and it is preserved exactly.
    const worst = scoreConditions([critical()]);
    const bad = scoreConditions([high()]);
    const middling = scoreConditions([medium()]);
    const slight = scoreConditions([info()]);

    expect(worst).toBeLessThan(bad);
    expect(bad).toBeLessThan(middling);
    expect(middling).toBeLessThan(slight);
    expect(slight).toBeLessThan(100);
  });

  it('empties the pillar rather than the score', () => {
    // Three findings worth 120 points between them, all about impersonation.
    // The pillar bottoms out at zero; the domain still delivers mail and still
    // has its hardening, and the total says so.
    const distinct = [
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DKIM_KEY_REVOKED', { selector: 's1', domain: 'a.com' }),
    ];
    const sum = scoreBreakdown(distinct);

    expect(sum.pillars.find((p) => p.pillar === 'IMPERSONATION')?.score).toBe(0);
    expect(sum.score).toBe(55);
  });

  it('charges the same problem once, however many times it was found', () => {
    // Three selectors with 1024-bit keys is one fix, not three.
    const repeated = [
      createCondition('DKIM_KEY_WEAK_1024', { selector: 'google' }),
      createCondition('DKIM_KEY_WEAK_1024', { selector: 's1' }),
      createCondition('DKIM_KEY_WEAK_1024', { selector: 'mandrill' }),
    ];
    expect(scoreConditions(repeated)).toBe(scoreConditions([repeated[0]!]));
  });

  it('still charges genuinely different problems separately', () => {
    const one = [createCondition('DKIM_KEY_WEAK_1024', { selector: 'google' })];
    const both = [
      createCondition('DKIM_KEY_WEAK_1024', { selector: 'google' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
    ];
    expect(scoreConditions(both)).toBeLessThan(scoreConditions(one));
  });
});

describe('rollupRecord', () => {
  it('is critical when anything is critical', () => {
    expect(rollupRecord([critical(), info()])).toBe('CRITICAL');
  });

  it('needs attention for HIGH or MEDIUM', () => {
    expect(rollupRecord([high()])).toBe('ATTENTION');
    expect(rollupRecord([medium()])).toBe('ATTENTION');
  });

  it('is healthy for advisories only, and for nothing at all', () => {
    expect(rollupRecord([info()])).toBe('HEALTHY');
    expect(rollupRecord([])).toBe('HEALTHY');
  });
});

describe('worstSeverity', () => {
  it('reports the most severe present', () => {
    expect(worstSeverity([info(), high(), medium()])).toBe('HIGH');
    expect(worstSeverity([])).toBeNull();
  });
});

describe('sortConditions', () => {
  it('triages most severe first', () => {
    const sorted = sortConditions([info(), medium(), critical(), high()]);
    expect(sorted.map((c) => c.severity)).toEqual(['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']);
  });

  it('does not mutate the input', () => {
    const input = [info(), critical()];
    sortConditions(input);
    expect(input[0]?.severity).toBe('INFO');
  });
});

describe('dedupeConditions', () => {
  it('collapses the same finding about the same thing', () => {
    const duplicate = [
      createCondition('SPF_PTR_MECHANISM', { offending_term: 'ptr' }),
      createCondition('SPF_PTR_MECHANISM', { offending_term: 'ptr' }),
    ];
    expect(dedupeConditions(duplicate)).toHaveLength(1);
  });

  it('keeps the same code about different things', () => {
    const distinct = [
      createCondition('SPF_PTR_MECHANISM', { offending_term: 'ptr' }),
      createCondition('SPF_PTR_MECHANISM', { offending_term: 'ptr:mail.example.com' }),
    ];
    expect(dedupeConditions(distinct)).toHaveLength(2);
  });
});

describe('the pillars', () => {
  it('keeps optional hardening away from the rest of the score', () => {
    // Every optional record missing at once. It is worth telling somebody
    // about and it is not what decides whether their mail arrives.
    const hardening = [
      createCondition('MTASTS_MISSING', { domain: 'a.com' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
      createCondition('BIMI_MISSING', { domain: 'a.com' }),
      createCondition('CAA_MISSING', { domain: 'a.com' }),
    ];

    // Hardening carries fifteen percent, so losing all of it cannot cost more
    // than fifteen points however many gaps there are.
    expect(scoreConditions(hardening)).toBeGreaterThanOrEqual(85);
  });

  it('charges impersonation far harder than tidiness', () => {
    const impersonation = [createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' })];
    const tidiness = [createCondition('SPF_EXTRA_WHITESPACE', { domain: 'a.com' })];

    expect(scoreConditions(impersonation)).toBeLessThan(scoreConditions(tidiness) - 10);
  });

  it('files each finding under the question it answers', () => {
    const sum = scoreBreakdown([
      createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('SPF_LOOKUP_LIMIT_EXCEEDED', { count: 12 }),
      createCondition('DMARC_RUA_MISSING', { domain: 'a.com' }),
      createCondition('CAA_MISSING', { domain: 'a.com' }),
    ]);

    const where = (code: string) =>
      sum.pillars.find((p) => p.findings.some((f) => f.code === code))?.pillar;

    expect(where('DMARC_RECORD_MISSING')).toBe('IMPERSONATION');
    expect(where('SPF_LOOKUP_LIMIT_EXCEEDED')).toBe('DELIVERY');
    expect(where('DMARC_RUA_MISSING')).toBe('VISIBILITY');
    expect(where('CAA_MISSING')).toBe('HARDENING');
  });

  it('never lets one catastrophe drag the whole score to nothing', () => {
    // This is the regression. online.sbi.bank.in scored 0 out of 100 with the
    // page beside it reading "Protected, your domain can't be easily spoofed",
    // because four findings summed past 100 in a single pool.
    const sbi = [
      createCondition('DMARC_EDV_MISSING', { domain: 'a.com', target: 'x.com' }),
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_POLICY_INHERITED', { domain: 'a.com', source_domain: 'b.com' }),
      createCondition('MX_MISSING', { domain: 'a.com' }),
      createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
      createCondition('BIMI_MISSING', { domain: 'a.com' }),
      createCondition('CAA_MISSING', { domain: 'a.com' }),
    ];

    expect(scoreConditions(sbi, { spoofability: 'PROTECTED' })).toBeGreaterThan(40);
  });

  it('a pillar cannot go below zero and take the others with it', () => {
    const everything = [
      createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DKIM_KEY_REVOKED', { selector: 's1', domain: 'a.com' }),
      createCondition('DMARC_V_CASE_INVALID', {}),
    ];
    const sum = scoreBreakdown(everything);

    expect(sum.pillars.find((p) => p.pillar === 'IMPERSONATION')?.score).toBe(0);
    // Delivery, visibility and hardening are untouched, so the total is not 0.
    expect(sum.score).toBeGreaterThan(0);
  });

  it('reproduces its own arithmetic', () => {
    const sum = scoreBreakdown([
      createCondition('MTASTS_MISSING', { domain: 'a.com' }),
      createCondition('DMARC_P_QUARANTINE', { domain: 'a.com' }),
    ]);

    const byHand =
      sum.pillars.reduce((total, p) => total + p.score * p.weight, 0) /
      sum.pillars.reduce((total, p) => total + p.weight, 0);

    expect(Math.round(byHand)).toBe(sum.score);
  });
});

describe('the score can never contradict the verdict', () => {
  it('does not call a protected domain critical', () => {
    // The whole point of the floor. A domain at p=reject refuses unauthenticated
    // mail whatever else is missing, so an impersonation score in the twenties
    // would be measuring hygiene and calling it exposure.
    const messy = [
      createCondition('SPF_RECORD_MISSING', { domain: 'a.com' }),
      createCondition('DKIM_KEY_REVOKED', { selector: 's1', domain: 'a.com' }),
      createCondition('DMARC_POLICY_INHERITED', { domain: 'a.com', source_domain: 'b.com' }),
    ];

    expect(scoreConditions(messy, { spoofability: 'PROTECTED' })).toBeGreaterThanOrEqual(50);
  });

  it('does not let a spoofable domain look healthy on hardening alone', () => {
    const spoofable = [createCondition('DMARC_RECORD_MISSING', { domain: 'a.com' })];
    const score = scoreConditions(spoofable, { spoofability: 'SPOOFABLE' });

    expect(score).toBeLessThanOrEqual(39);
  });

  it('caps a spoofable domain that is otherwise spotless', () => {
    const sum = scoreBreakdown([createCondition('DMARC_P_NONE', { domain: 'a.com' })], {
      spoofability: 'SPOOFABLE',
    });

    expect(sum.score).toBeLessThanOrEqual(39);
  });

  it('keeps quarantine below healthy however clean the rest is', () => {
    // p=quarantine is genuinely better than nothing and genuinely not the
    // finish line. A perfect domain sitting at quarantine tops out just under
    // the healthy band, which is the nudge to reject.
    expect(scoreConditions([], { spoofability: 'PARTIAL' })).toBe(64);
  });
});

describe('vitals', () => {
  it.each([
    [100, 'HEALTHY'],
    [85, 'HEALTHY'],
    [84, 'NEEDS_CARE'],
    [65, 'NEEDS_CARE'],
    [64, 'AT_RISK'],
    [40, 'AT_RISK'],
    [39, 'CRITICAL'],
    [0, 'CRITICAL'],
  ])('scores %i as %s', (score, band) => {
    expect(vitalsBand(score)).toBe(band);
  });

  it('assembles the monitor readout', () => {
    const readout = vitals([critical(), high()]);
    // Both are impersonation findings: 100 - 65 = 35 on a pillar worth 45
    // percent, with the other three pillars untouched.
    expect(readout.score).toBe(71);
    expect(readout.band).toBe('NEEDS_CARE');
    expect(readout.counts.CRITICAL).toBe(1);
    expect(readout.counts.HIGH).toBe(1);
    expect(readout.counts.LOW).toBe(0);
  });
});

describe('scoreBreakdown', () => {
  it('agrees with scoreConditions on every shape', () => {
    const samples = [
      [],
      [createCondition('SPF_RECORD_MISSING', { domain: 'a.com' })],
      [
        createCondition('DKIM_KEY_WEAK_1024', { selector: 's1' }),
        createCondition('DKIM_KEY_WEAK_1024', { selector: 's2' }),
        createCondition('DNSSEC_UNSIGNED', { domain: 'a.com' }),
      ],
    ];

    for (const sample of samples) {
      expect(scoreBreakdown(sample).score).toBe(scoreConditions(sample));
    }
  });
});
